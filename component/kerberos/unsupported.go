//go:build !windows && !((darwin || (linux && with_gssapi)) && !android && !ios && (amd64 || arm64))

package kerberos

import (
	"fmt"
	"runtime"
)

func CheckSupport() error {
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		return fmt.Errorf("system Kerberos authentication on Linux requires a build with the with_gssapi tag")
	}
	return fmt.Errorf("system Kerberos authentication is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}

func newClient(string) (Client, error) {
	return nil, CheckSupport()
}
