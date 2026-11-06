//go:build darwin && !ios && (amd64 || arm64)

package kerberos

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	helperLifetime   = 30 * time.Second
	maxHelperMessage = 2 << 20
	maxHelperRounds  = 16
)

type helperRequest struct {
	SPN   string `json:"spn,omitempty"`
	Token []byte `json:"token,omitempty"`
}

type helperResponse struct {
	Token    []byte `json:"token,omitempty"`
	Complete bool   `json:"complete,omitempty"`
	Error    string `json:"error,omitempty"`
}

type helperClient struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output io.ReadCloser
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func startHelperClient(ctx context.Context, spn string, command func(context.Context) *exec.Cmd) (Client, error) {
	ctx, cancel := context.WithTimeout(ctx, helperLifetime)
	c := &helperClient{ctx: ctx, cancel: cancel}
	c.cmd = command(ctx)
	// launchctl and the helper belong to a dedicated group, so cancellation
	// terminates both even when launchctl waits for its child process.
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.cmd.Cancel = func() error {
		err := syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	c.cmd.WaitDelay = time.Second
	var err error
	c.input, err = c.cmd.StdinPipe()
	if err == nil {
		c.output, err = c.cmd.StdoutPipe()
	}
	if err == nil {
		err = c.cmd.Start()
	}
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("start Kerberos helper: %w", err)
	}
	if _, err := c.exchange(helperRequest{SPN: spn}); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *helperClient) exchange(request helperRequest) (helperResponse, error) {
	var response helperResponse
	if err := c.ctx.Err(); err != nil {
		return response, err
	}
	err := writeHelperMessage(c.input, request)
	if err == nil {
		err = readHelperMessage(c.output, &response)
	}
	if err != nil {
		if contextErr := c.ctx.Err(); contextErr != nil {
			return response, contextErr
		}
		return response, fmt.Errorf("communicate with Kerberos helper: %w", err)
	}
	if response.Error != "" {
		return response, fmt.Errorf("console-user Kerberos: %s", response.Error)
	}
	return response, nil
}

func (c *helperClient) Next(token []byte) ([]byte, bool, error) {
	response, err := c.exchange(helperRequest{Token: token})
	return response.Token, response.Complete, err
}

func (c *helperClient) Close() error {
	c.once.Do(func() {
		c.cancel()
		if c.input != nil {
			c.input.Close()
		}
		if c.output != nil {
			c.output.Close()
		}
		if c.cmd.Process != nil {
			_ = c.cmd.Cancel()
			_ = c.cmd.Wait()
		}
	})
	return nil
}

func serveHelper(input io.Reader, output io.Writer, create func(string) (Client, error)) error {
	var request helperRequest
	if err := readHelperMessage(input, &request); err != nil {
		return err
	}
	if err := ValidateSPN(request.SPN); err != nil {
		return writeHelperMessage(output, helperResponse{Error: err.Error()})
	}
	client, err := create(request.SPN)
	if err != nil {
		return writeHelperMessage(output, helperResponse{Error: err.Error()})
	}
	defer client.Close()
	if err := writeHelperMessage(output, helperResponse{}); err != nil {
		return err
	}
	for round := 0; round < maxHelperRounds; round++ {
		request = helperRequest{}
		if err := readHelperMessage(input, &request); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if request.SPN != "" {
			return errors.New("cannot change a Kerberos helper's service principal")
		}
		token, complete, err := client.Next(request.Token)
		response := helperResponse{Token: token, Complete: complete}
		if err != nil {
			response = helperResponse{Error: err.Error()}
		}
		if writeErr := writeHelperMessage(output, response); writeErr != nil {
			return writeErr
		}
		if err != nil {
			return nil
		}
	}
	return errors.New("too many Kerberos helper authentication rounds")
}

func writeHelperMessage(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxHelperMessage {
		return errors.New("Kerberos helper message is too large")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	for _, part := range [][]byte{length[:], data} {
		n, err := w.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readHelperMessage(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxHelperMessage {
		return errors.New("invalid Kerberos helper message size")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
