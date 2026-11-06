//go:build darwin && !ios && (amd64 || arm64)

package kerberos

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type testHelperClient struct {
	block bool
}

func (c *testHelperClient) Next(token []byte) ([]byte, bool, error) {
	if c.block {
		time.Sleep(time.Minute)
	}
	if len(token) == 0 {
		return []byte("initial"), false, nil
	}
	if string(token) != "server" {
		return nil, false, errors.New("invalid server token")
	}
	return nil, true, nil
}

func (*testHelperClient) Close() error { return nil }

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "kerberos-helper" {
		if RunHelper(os.Args[2:]) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) > 2 && os.Args[1] == "kerberos-test-helper" {
		mode := os.Args[2]
		if mode == "exit" {
			os.Exit(3)
		}
		err := serveHelper(os.Stdin, os.Stdout, func(spn string) (Client, error) {
			if spn != "HTTP/proxy.example" {
				return nil, errors.New("unexpected SPN")
			}
			if mode == "no-credentials" {
				return nil, errors.New("no system credentials")
			}
			return &testHelperClient{block: mode == "block"}, nil
		})
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testHelperCommand(t *testing.T, mode string) func(context.Context) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, executable, "kerberos-test-helper", mode)
	}
}

func TestHelperNegotiation(t *testing.T) {
	client, err := startHelperClient(context.Background(), "HTTP/proxy.example", testHelperCommand(t, "normal"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	token, complete, err := client.Next(nil)
	if err != nil || complete || string(token) != "initial" {
		t.Fatalf("unexpected initial result: complete=%t, error=%v", complete, err)
	}
	token, complete, err = client.Next([]byte("server"))
	if err != nil || !complete || len(token) != 0 {
		t.Fatalf("unexpected final result: complete=%t, error=%v", complete, err)
	}
	client.Close()
	client.Close()
	if client.(*helperClient).cmd.ProcessState == nil {
		t.Fatal("helper process was not reaped")
	}
	if _, _, err := client.Next(nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed helper accepted authentication: %v", err)
	}
}

func TestHelperErrors(t *testing.T) {
	for _, mode := range []string{"no-credentials", "exit"} {
		t.Run(mode, func(t *testing.T) {
			var command *exec.Cmd
			factory := testHelperCommand(t, mode)
			_, err := startHelperClient(context.Background(), "HTTP/proxy.example", func(ctx context.Context) *exec.Cmd {
				command = factory(ctx)
				return command
			})
			if err == nil {
				t.Fatal("failed helper accepted authentication")
			}
			if mode == "no-credentials" && !strings.Contains(err.Error(), "no system credentials") {
				t.Fatalf("native error was lost: %v", err)
			}
			if command.ProcessState == nil {
				t.Fatal("failed helper process was not reaped")
			}
		})
	}
}

func TestHelperCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := startHelperClient(ctx, "HTTP/proxy.example", testHelperCommand(t, "block"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _, err = client.Next(nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked native helper did not honor deadline: %v", err)
	}
	client.Close()
	if client.(*helperClient).cmd.ProcessState == nil {
		t.Fatal("cancelled helper process was not reaped")
	}
}

func TestHelperRejectsInvalidServerToken(t *testing.T) {
	client, err := startHelperClient(context.Background(), "HTTP/proxy.example", testHelperCommand(t, "normal"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, complete, err := client.Next([]byte("invalid"))
	if err == nil || complete || !strings.Contains(err.Error(), "invalid server token") {
		t.Fatalf("lost native token validation: complete=%t, error=%v", complete, err)
	}
}

func TestHelperMessageBounds(t *testing.T) {
	for _, size := range []uint32{0, maxHelperMessage + 1, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		var response helperResponse
		if err := readHelperMessage(bytes.NewReader(header[:]), &response); err == nil {
			t.Fatalf("accepted invalid size %d", size)
		}
	}
	if err := writeHelperMessage(io.Discard, helperRequest{Token: make([]byte, maxHelperMessage)}); err == nil {
		t.Fatal("accepted oversized outgoing token")
	}
}

func TestHelperRejectsInvalidIdentity(t *testing.T) {
	for _, args := range [][]string{nil, {"0", "0"}, {"-1", "20"}, {"4294967296", "20"}, {"501", "bad"}} {
		if err := prepareConsoleHelper(args); err == nil {
			t.Fatalf("accepted invalid helper identity %v", args)
		}
	}
}

// Opt in to exercise launchctl, the actual helper entry point and the current
// console user's system GSS credentials without exporting or logging tickets.
func TestConsoleUserKerberosIntegration(t *testing.T) {
	spn := os.Getenv("MIHOMO_KERBEROS_CONSOLE_TEST_SPN")
	if spn == "" {
		t.Skip("set MIHOMO_KERBEROS_CONSOLE_TEST_SPN to test console-user credentials")
	}
	identity, err := currentConsoleUser()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := newConsoleClient(ctx, identity, spn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	token, complete, err := client.Next(nil)
	if err != nil || complete || len(token) == 0 {
		t.Fatalf("failed to initialize console-user Kerberos: complete=%t, error=%v", complete, err)
	}
}
