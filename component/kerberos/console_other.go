//go:build !darwin || ios || (!amd64 && !arm64)

package kerberos

import (
	"context"
	"errors"
)

func fallbackConsoleClient(_ context.Context, _ string, err error) (Client, error) {
	return nil, err
}

// RunHelper is only supported by the macOS system-identity backend.
func RunHelper([]string) error {
	return errors.New("the Kerberos console-user helper is only supported on macOS")
}
