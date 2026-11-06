package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/kerberos"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

type httpTestKerberosClient struct {
	step   func([]byte) ([]byte, bool, error)
	closed chan struct{}
}

func (c *httpTestKerberosClient) Next(token []byte) ([]byte, bool, error) { return c.step(token) }
func (c *httpTestKerberosClient) Close() error                            { close(c.closed); return nil }

func TestHttpKerberos(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint("chunked=", chunked), func(t *testing.T) {
			calls := 0
			auth := &httpTestKerberosClient{closed: make(chan struct{})}
			auth.step = func(token []byte) ([]byte, bool, error) {
				calls++
				switch calls {
				case 1:
					if len(token) != 0 {
						return nil, false, errors.New("unexpected initial token")
					}
					return []byte("first"), false, nil
				case 2:
					if string(token) != "challenge" {
						return nil, false, errors.New("wrong challenge")
					}
					return []byte("second"), false, nil
				case 3:
					if string(token) != "final" {
						return nil, false, errors.New("wrong final token")
					}
					return nil, true, nil
				default:
					return nil, false, errors.New("unexpected extra authentication round")
				}
			}
			h := httpWithTestKerberos(auth)
			h.option.KerberosMutualAuth = true
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			serverResult := make(chan error, 1)
			go func() {
				br := bufio.NewReader(server)
				for i, expected := range []string{"first", "second"} {
					req, err := http.ReadRequest(br)
					if err != nil {
						serverResult <- err
						return
					}
					if req.Method != "CONNECT" || req.Host != "destination.example:443" ||
						req.Header.Get("Proxy-Authorization") != "Negotiate "+base64.StdEncoding.EncodeToString([]byte(expected)) ||
						req.Header.Get("X-Test") != "kept" {
						serverResult <- errors.New("incorrect CONNECT request")
						return
					}
					response := "HTTP/1.1 200 Connection established\r\nProxy-Authenticate: Negotiate ZmluYWw=\r\n\r\ntunnel bytes"
					if i == 0 {
						response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fallback\", nEgOtIaTe Y2hhbGxlbmdl\r\nContent-Length: 4\r\n\r\nbody"
						if chunked {
							response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate Y2hhbGxlbmdl\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"
						}
					}
					if _, err = io.WriteString(server, response); err != nil {
						serverResult <- err
						return
					}
				}
				serverResult <- nil
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "destination.example", DstPort: 443})
			if err != nil {
				t.Fatal(err)
			}
			data := make([]byte, len("tunnel bytes"))
			if _, err := io.ReadFull(conn, data); err != nil {
				t.Fatal(err)
			}
			if string(data) != "tunnel bytes" {
				t.Fatalf("lost buffered tunnel data: %q", data)
			}
			if err := <-serverResult; err != nil {
				t.Fatal(err)
			}
			<-auth.closed
			if calls != 3 {
				t.Fatalf("got %d authentication calls", calls)
			}
		})
	}
}

func httpWithTestKerberos(auth kerberos.Client) *Http {
	return &Http{
		option: &HttpOption{Kerberos: true, KerberosSPN: "HTTP/proxy.example", Headers: map[string]string{"X-Test": "kept"}},
		newKerberosClient: func(_ context.Context, spn string) (kerberos.Client, error) {
			if spn != "HTTP/proxy.example" {
				return nil, fmt.Errorf("wrong SPN: %s", spn)
			}
			return auth, nil
		},
	}
}

func TestHttpKerberosOptionalMutualAuth(t *testing.T) {
	for _, header := range []string{"", "Proxy-Authenticate: Negotiate\r\n"} {
		t.Run(fmt.Sprintf("header=%q", header), func(t *testing.T) {
			auth := &httpTestKerberosClient{closed: make(chan struct{}), step: func(token []byte) ([]byte, bool, error) {
				if len(token) != 0 {
					return nil, false, errors.New("unexpected server token")
				}
				return []byte("initial"), false, nil
			}}
			h := httpWithTestKerberos(auth)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			result := make(chan error, 1)
			go func() {
				_, err := http.ReadRequest(bufio.NewReader(server))
				if err == nil {
					_, err = io.WriteString(server, "HTTP/1.1 200 Connection established\r\n"+header+"\r\ntunnel bytes")
				}
				result <- err
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "target", DstPort: 443})
			if err != nil {
				t.Fatal(err)
			}
			data := make([]byte, len("tunnel bytes"))
			if _, err := io.ReadFull(conn, data); err != nil {
				t.Fatal(err)
			}
			if string(data) != "tunnel bytes" {
				t.Fatalf("lost tunnel data: %q", data)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			<-auth.closed
		})
	}
}

func TestHttpKerberosFailures(t *testing.T) {
	for _, tc := range []struct {
		name, response, want string
		mutualAuth           bool
	}{
		{"basic only", "407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0", "does not offer Negotiate", false},
		{"rejected", "407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nContent-Length: 0", "rejected system credentials", false},
		{"bad base64", "407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate !!!\r\nContent-Length: 0", "invalid base64", false},
		{"bad final base64", "200 Connection established\r\nProxy-Authenticate: Negotiate !!!", "invalid base64", false},
		{"closed", "407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate YQ==\r\nConnection: close\r\nContent-Length: 0", "closed the connection", false},
		{"unframed", "407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate YQ==", "closed the connection", false},
		{"missing mutual auth", "200 Connection established", "did not complete mutual authentication", true},
		{"empty mutual auth", "200 Connection established\r\nProxy-Authenticate: Negotiate", "did not complete mutual authentication", true},
		{"invalid server token", "200 Connection established\r\nProxy-Authenticate: Negotiate YQ==", "verify proxy token", false},
		{"method not allowed", "405 Method Not Allowed", "CONNECT method not allowed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &httpTestKerberosClient{closed: make(chan struct{}), step: func(token []byte) ([]byte, bool, error) {
				if len(token) > 0 {
					return nil, false, errors.New("invalid AP-REP")
				}
				return []byte("first"), false, nil
			}}
			h := httpWithTestKerberos(auth)
			h.option.KerberosMutualAuth = tc.mutualAuth
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
					io.WriteString(server, "HTTP/1.1 "+tc.response+"\r\n\r\n")
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "target", DstPort: 443})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			<-auth.closed
		})
	}
}

func TestHttpKerberosFinalToken(t *testing.T) {
	for _, tc := range []struct {
		name, output, want string
		complete           bool
	}{
		{"complete", "", "", true},
		{"incomplete", "", "did not complete mutual authentication", false},
		{"pending token", "pending", "before negotiation finished", false},
		{"complete with pending token", "pending", "before negotiation finished", true},
	} {
		for _, mutualAuth := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mutual=%t", tc.name, mutualAuth), func(t *testing.T) {
				calls := 0
				auth := &httpTestKerberosClient{closed: make(chan struct{}), step: func(token []byte) ([]byte, bool, error) {
					calls++
					if calls == 1 && len(token) == 0 {
						return []byte("initial"), false, nil
					}
					if calls != 2 || string(token) != "final" {
						return nil, false, errors.New("unexpected server token")
					}
					return []byte(tc.output), tc.complete, nil
				}}
				h := httpWithTestKerberos(auth)
				h.option.KerberosMutualAuth = mutualAuth
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				go func() {
					if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
						io.WriteString(server, "HTTP/1.1 200 Connection established\r\nProxy-Authenticate: Negotiate ZmluYWw=\r\n\r\n")
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "target", DstPort: 443})
				if tc.want == "" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %q", err, tc.want)
				}
				<-auth.closed
				if calls != 2 {
					t.Fatalf("got %d authentication calls", calls)
				}
			})
		}
	}
}

func TestHttpKerberosCancellation(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	auth := &httpTestKerberosClient{closed: make(chan struct{}), step: func([]byte) ([]byte, bool, error) {
		close(started)
		<-resume
		return []byte("token"), false, nil
	}}
	h := httpWithTestKerberos(auth)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "target", DstPort: 443})
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Error("cancellation waited for the native authentication call")
	}
	select {
	case <-auth.closed:
		t.Error("released a context still in use")
	default:
	}
	close(resume)
	select {
	case <-auth.closed:
	case <-time.After(time.Second):
		t.Fatal("context was not released after native call returned")
	}
}

func TestHttpBasic(t *testing.T) {
	h, err := NewHttp(HttpOption{Server: "proxy.example", Port: 8080, UserName: "user", Password: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	result := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(server))
		if err == nil && req.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			err = errors.New("Basic authorization changed")
		}
		if err == nil {
			_, err = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\n")
		}
		result <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "target", DstPort: 443}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestHttpKerberosOptions(t *testing.T) {
	if err := kerberos.CheckSupport(); err != nil {
		t.Skip(err)
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy"})
	var option HttpOption
	config := map[string]any{"name": "system", "server": "Proxy.Example.", "port": 8080, "kerberos": true}
	if err := decoder.Decode(config, &option); err != nil {
		t.Fatal(err)
	}
	h, err := NewHttp(option)
	if err != nil {
		t.Fatal(err)
	}
	if h.option.KerberosSPN != "HTTP/proxy.example" {
		t.Fatal(h.option.KerberosSPN)
	}
	if h.option.KerberosMutualAuth {
		t.Fatal("mutual authentication should be optional by default")
	}
	config["kerberos-mutual-auth"] = true
	if err := decoder.Decode(config, &option); err != nil {
		t.Fatal(err)
	}
	option.KerberosSPN = "HTTP/registered.example@EXAMPLE.COM"
	h, err = NewHttp(option)
	if err != nil {
		t.Fatal(err)
	}
	if h.option.KerberosSPN != option.KerberosSPN {
		t.Fatal("explicit SPN changed")
	}
	if !h.option.KerberosMutualAuth {
		t.Fatal("mutual authentication option was not decoded")
	}
	for _, modify := range []func(*HttpOption){
		func(o *HttpOption) { o.UserName = "user" },
		func(o *HttpOption) { o.Password = "pass" },
		func(o *HttpOption) { o.Headers = map[string]string{"proxy-authorization": "Basic x"} },
		func(o *HttpOption) { o.KerberosSPN = "bad" },
		func(o *HttpOption) { o.KerberosSPN = "HTTP/host\x00" },
		func(o *HttpOption) { o.Kerberos = false },
	} {
		invalid := option
		modify(&invalid)
		if _, err := NewHttp(invalid); err == nil {
			t.Fatalf("accepted invalid options: %+v", invalid)
		}
	}
}

func TestHttpKerberosMutualAuthRequiresKerberos(t *testing.T) {
	_, err := NewHttp(HttpOption{Server: "proxy.example", Port: 8080, KerberosMutualAuth: true})
	if err == nil || !strings.Contains(err.Error(), "kerberos-mutual-auth requires kerberos: true") {
		t.Fatalf("got %v", err)
	}
}

func TestHttpProxyNegotiateToken(t *testing.T) {
	for _, tc := range []struct {
		value   string
		offered bool
		token   string
	}{
		{`Basic realm="x, Negotiate YQ=="`, false, ""},
		{`Basic realm="x, Negotiate YQ==", nEgOtIaTe Yg==`, true, "b"},
		{"Negotiate", true, ""},
		{"NegotiateX YQ==", false, ""},
	} {
		token, offered, err := proxyNegotiateToken(http.Header{"Proxy-Authenticate": {tc.value}})
		if err != nil || offered != tc.offered || string(token) != tc.token {
			t.Fatalf("%q: %q %v %v", tc.value, token, offered, err)
		}
	}
	token, offered, err := proxyNegotiateToken(http.Header{"Proxy-Authenticate": {"Basic realm=x", "Negotiate", "Negotiate YQ=="}})
	if err != nil || !offered || string(token) != "a" {
		t.Fatalf("multiple headers: %q %v %v", token, offered, err)
	}
}

func TestHttpKerberosRoundLimit(t *testing.T) {
	auth := &httpTestKerberosClient{closed: make(chan struct{}), step: func([]byte) ([]byte, bool, error) {
		return []byte("token"), false, nil
	}}
	h := httpWithTestKerberos(auth)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	served := make(chan int, 1)
	go func() {
		br := bufio.NewReader(server)
		requests := 0
		for requests < maxKerberosRounds {
			if _, err := http.ReadRequest(br); err != nil {
				break
			}
			requests++
			if _, err := io.WriteString(server, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate YQ==\r\nContent-Length: 0\r\n\r\n"); err != nil {
				break
			}
		}
		served <- requests
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "target", DstPort: 443})
	if err == nil || !strings.Contains(err.Error(), "too many authentication rounds") {
		t.Fatalf("got %v", err)
	}
	if requests := <-served; requests != maxKerberosRounds {
		t.Fatalf("got %d requests", requests)
	}
	<-auth.closed
}

func TestHttpKerberosChallengeBodyLimit(t *testing.T) {
	response := fmt.Sprintf("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: %d\r\n\r\n", maxProxyAuthBody+1) + strings.Repeat("x", maxProxyAuthBody+1)
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(response)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := drainProxyAuthResponse(resp); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v", err)
	}
}
