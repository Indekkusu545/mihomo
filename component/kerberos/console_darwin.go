//go:build darwin && !ios && (amd64 || arm64)

package kerberos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/ebitengine/purego"
)

type consoleIdentity struct {
	uid, gid uint32
}

// Resolve the foreground console user for each handshake, including after fast
// user switching. A login window or a headless system must not select root.
func currentConsoleUser() (consoleIdentity, error) {
	var identity consoleIdentity
	handle, err := purego.Dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return identity, fmt.Errorf("load SystemConfiguration: %w", err)
	}
	defer purego.Dlclose(handle)
	copySymbol, err := purego.Dlsym(handle, "SCDynamicStoreCopyConsoleUser")
	if err != nil {
		return identity, err
	}
	releaseSymbol, err := purego.Dlsym(handle, "CFRelease")
	if err != nil {
		return identity, err
	}
	var copyUser func(uintptr, *uint32, *uint32) uintptr
	var release func(uintptr)
	purego.RegisterFunc(&copyUser, copySymbol)
	purego.RegisterFunc(&release, releaseSymbol)
	name := copyUser(0, &identity.uid, &identity.gid)
	if name != 0 {
		release(name)
	}
	if name == 0 || identity.uid == 0 || identity.uid == ^uint32(0) || identity.gid == ^uint32(0) {
		return consoleIdentity{}, errors.New("no active macOS console user is available for Kerberos authentication")
	}
	return identity, nil
}

func fallbackConsoleClient(ctx context.Context, spn string, original error) (Client, error) {
	// Preserve service credentials and explicit cache/keytab selection. Only a
	// root process with GSS_S_NO_CRED may fall back to the desktop session.
	var status *gssStatusError
	if os.Geteuid() != 0 || os.Getenv("KRB5CCNAME") != "" || os.Getenv("KRB5_CLIENT_KTNAME") != "" ||
		!errors.As(original, &status) || status.major&0xff0000 != 7<<16 {
		return nil, original
	}
	identity, err := currentConsoleUser()
	if err == nil {
		var client Client
		client, err = newConsoleClient(ctx, identity, spn)
		if err == nil {
			return client, nil
		}
	}
	return nil, fmt.Errorf("%w; macOS console-user authentication: %v", original, err)
}

func newConsoleClient(ctx context.Context, identity consoleIdentity, spn string) (Client, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// asuser changes the bootstrap/audit session, but not UID/GID. The helper
	// verifies the console user again and drops privileges before loading GSS.
	return startHelperClient(ctx, spn, func(ctx context.Context) *exec.Cmd {
		command := exec.CommandContext(ctx, "/bin/launchctl", "asuser", strconv.FormatUint(uint64(identity.uid), 10),
			executable, "kerberos-helper", strconv.FormatUint(uint64(identity.uid), 10), strconv.FormatUint(uint64(identity.gid), 10))
		command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
		return command
	})
}

func prepareConsoleHelper(args []string) error {
	if len(args) != 2 {
		return errors.New("invalid Kerberos helper arguments")
	}
	uid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return errors.New("invalid Kerberos helper UID")
	}
	gid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return errors.New("invalid Kerberos helper GID")
	}
	identity, err := currentConsoleUser()
	if err != nil {
		return err
	}
	if uint64(identity.uid) != uid || uint64(identity.gid) != gid {
		return errors.New("the active macOS console user changed before Kerberos authentication")
	}
	account, err := user.LookupId(args[0])
	if err != nil {
		return fmt.Errorf("resolve console user: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups([]int{int(gid)}); err != nil {
			return fmt.Errorf("drop helper supplementary groups: %w", err)
		}
		if err := syscall.Setgid(int(gid)); err != nil {
			return fmt.Errorf("drop helper GID: %w", err)
		}
		if err := syscall.Setuid(int(uid)); err != nil {
			return fmt.Errorf("drop helper UID: %w", err)
		}
	}
	if os.Getuid() != int(uid) || os.Geteuid() != int(uid) || os.Getgid() != int(gid) || os.Getegid() != int(gid) {
		return errors.New("Kerberos helper must run as the active console user")
	}
	// Do not inherit a service's credential cache, keytab, or library settings.
	os.Clearenv()
	for key, value := range map[string]string{
		"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": account.HomeDir,
		"USER": account.Username, "LOGNAME": account.Username,
	} {
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return os.Chdir("/")
}

// RunHelper serves a single authentication context over inherited anonymous
// pipes. It never opens a listener or exports a ticket cache. The main process
// retains its service privileges and its original audit session.
func RunHelper(args []string) error {
	// Also bound orphaned helpers if the parent exits during a native GSS call.
	timer := time.AfterFunc(helperLifetime, func() { os.Exit(1) })
	defer timer.Stop()
	if err := prepareConsoleHelper(args); err != nil {
		_ = writeHelperMessage(os.Stdout, helperResponse{Error: err.Error()})
		return err
	}
	return serveHelper(os.Stdin, os.Stdout, newClient)
}
