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

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

const (
	maxKerberosRounds = 8
	maxProxyAuthBody  = 1 << 20
)

func (h *Http) kerberosHandshake(ctx context.Context, conn net.Conn, br *bufio.Reader, metadata *C.Metadata) error {
	client, err := h.newKerberosClient(ctx, h.option.KerberosSPN)
	if err != nil {
		return fmt.Errorf("HTTP Kerberos: %w", err)
	}
	defer client.Close()
	if err := ctx.Err(); err != nil {
		return err
	}

	// Send an initial token proactively, as with Basic authentication. This
	// also works with proxies that close unauthenticated CONNECT connections.
	token, complete, err := client.Next(nil)
	for round := 0; round < maxKerberosRounds; round++ {
		if err != nil {
			return fmt.Errorf("HTTP Kerberos: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(token) == 0 {
			return errors.New("HTTP Kerberos: empty client token")
		}
		resp, err := h.connect(conn, br, metadata, "Negotiate "+base64.StdEncoding.EncodeToString(token))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusProxyAuthRequired {
			return httpConnectError(resp)
		}
		challenge, offered, err := proxyNegotiateToken(resp.Header)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			// Do not read or close resp.Body: bytes after a successful CONNECT
			// belong to the tunnel, including bytes already buffered in br.
			if len(challenge) > 0 {
				token, complete, err = client.Next(challenge)
				if err != nil {
					return fmt.Errorf("HTTP Kerberos: verify proxy token: %w", err)
				}
				if len(token) > 0 {
					return errors.New("HTTP Kerberos: proxy established tunnel before negotiation finished")
				}
			}
			// Some proxies accept the client token but omit the final token.
			// Allow this unless mutual authentication is required, but always
			// require a supplied proxy token to finish the security context.
			if !complete && (h.option.KerberosMutualAuth || len(challenge) > 0) {
				return errors.New("HTTP Kerberos: proxy did not complete mutual authentication")
			}
			return nil
		}
		if !offered {
			return errors.New("HTTP Kerberos: proxy does not offer Negotiate authentication")
		}
		if complete || len(challenge) == 0 {
			return errors.New("HTTP Kerberos: proxy rejected system credentials")
		}
		if err := drainProxyAuthResponse(resp); err != nil {
			return err
		}
		token, complete, err = client.Next(challenge)
	}
	return errors.New("HTTP Kerberos: too many authentication rounds")
}

func drainProxyAuthResponse(resp *http.Response) error {
	if resp.Close || (resp.ContentLength < 0 && len(resp.TransferEncoding) == 0) ||
		strings.EqualFold(resp.Header.Get("Proxy-Connection"), "close") {
		return errors.New("HTTP Kerberos: proxy closed the connection during authentication")
	}
	// A challenge body must be consumed before the next CONNECT, but an
	// unbounded body must not keep authentication alive indefinitely.
	n, err := io.CopyN(io.Discard, resp.Body, maxProxyAuthBody+1)
	if n > maxProxyAuthBody {
		return errors.New("HTTP Kerberos: proxy authentication response body is too large")
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("HTTP Kerberos: read proxy authentication response: %w", err)
	}
	return resp.Body.Close()
}

// Proxy-Authenticate can contain multiple fields and comma-separated schemes.
// Quoted auth parameters may themselves contain commas or the word Negotiate.
func proxyNegotiateToken(header http.Header) ([]byte, bool, error) {
	offered := false
	for _, value := range header.Values("Proxy-Authenticate") {
		start, quoted, escaped := 0, false, false
		for i := 0; i <= len(value); i++ {
			if i < len(value) {
				if escaped {
					escaped = false
					continue
				}
				if quoted && value[i] == '\\' {
					escaped = true
					continue
				}
				if value[i] == '"' {
					quoted = !quoted
				}
				if value[i] != ',' || quoted {
					continue
				}
			}
			parts := strings.Fields(value[start:i])
			start = i + 1
			if len(parts) == 0 || !strings.EqualFold(parts[0], "Negotiate") {
				continue
			}
			if len(parts) == 1 {
				offered = true
				continue
			}
			if len(parts) != 2 || len(parts[1]) > maxProxyAuthBody {
				return nil, true, errors.New("HTTP Kerberos: invalid Negotiate challenge")
			}
			token, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, true, errors.New("HTTP Kerberos: invalid base64 in Negotiate challenge")
			}
			return token, true, nil
		}
	}
	return nil, offered, nil
}
