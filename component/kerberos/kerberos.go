// Package kerberos authenticates using the identity of the process through the
// operating system's SSPI or GSS-API implementation.
package kerberos

import (
	"errors"
	"strings"
)

// Client owns one SPNEGO security context. It must not be used concurrently or
// shared between connections. Close must be called even if Next fails.
type Client interface {
	// Next consumes a server token (nil for the first call) and returns a token
	// to send to the proxy and whether authentication has completed locally.
	Next(token []byte) (output []byte, complete bool, err error)
	Close() error
}

// NewClient uses the current process identity; it never prompts for credentials.
func NewClient(spn string) (Client, error) {
	if err := ValidateSPN(spn); err != nil {
		return nil, err
	}
	return newClient(spn)
}

func ValidateSPN(spn string) error {
	service, host, ok := strings.Cut(spn, "/")
	if !ok || service == "" || host == "" || strings.ContainsAny(spn, "\x00\r\n\t ") ||
		strings.ContainsAny(service, "@\\") || strings.Contains(host, "/") || strings.HasPrefix(host, "@") || strings.HasSuffix(host, "@") {
		return errors.New("Kerberos SPN must have the form service/hostname")
	}
	return nil
}
