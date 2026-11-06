//go:build (darwin || (linux && with_gssapi)) && !android && !ios && (amd64 || arm64)

package kerberos

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// These layouts follow RFC 2744. OM_uint32 is 32 bits, while size_t and
// opaque handles are pointer-sized. All buffers returned by GSS are released
// by GSS, after copying their contents into Go memory.
type gssBuffer struct {
	length uintptr
	value  *byte
}

type gssOID struct {
	length   uint32
	elements *byte
}

type gssOIDSet struct {
	count    uintptr
	elements *gssOID
}

var (
	krb5OIDBytes        = [...]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	spnegoOIDBytes      = [...]byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	principalOIDBytes   = [...]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01}
	krb5OID             = gssOID{uint32(len(krb5OIDBytes)), &krb5OIDBytes[0]}
	spnegoOID           = gssOID{uint32(len(spnegoOIDBytes)), &spnegoOIDBytes[0]}
	principalOID        = gssOID{uint32(len(principalOIDBytes)), &principalOIDBytes[0]}
	hostServiceOIDBytes = [...]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04}
	hostServiceOID      = gssOID{uint32(len(hostServiceOIDBytes)), &hostServiceOIDBytes[0]}
)

const (
	gssContinueNeeded = 1
	gssMutualFlag     = 2
)

type gssAPI struct {
	importName       func(*uint32, *gssBuffer, *gssOID, *uintptr) uint32
	releaseName      func(*uint32, *uintptr) uint32
	acquireCred      func(*uint32, uintptr, uint32, *gssOIDSet, int32, *uintptr, *uintptr, *uint32) uint32
	releaseCred      func(*uint32, *uintptr) uint32
	initSecContext   func(*uint32, uintptr, *uintptr, uintptr, *gssOID, uint32, uint32, uintptr, *gssBuffer, *uintptr, *gssBuffer, *uint32, *uint32) uint32
	deleteSecContext func(*uint32, *uintptr, *gssBuffer) uint32
	releaseBuffer    func(*uint32, *gssBuffer) uint32
	displayStatus    func(*uint32, uint32, int32, *gssOID, *uint32, *gssBuffer) uint32
}

var (
	gssOnce      sync.Once
	gssLibrary   gssAPI
	gssLoadError error
)

// CheckSupport checks the build target without loading native libraries or
// acquiring credentials. Ordinary HTTP nodes never load GSS.
func CheckSupport() error { return nil }

func loadGSS() (*gssAPI, error) {
	gssOnce.Do(func() {
		libraries := []string{"libgssapi_krb5.so.2", "libgssapi.so.3", "libgssapi.so"}
		if runtime.GOOS == "darwin" {
			libraries = []string{"/System/Library/Frameworks/GSS.framework/GSS"}
		}
		var handle uintptr
		for _, name := range libraries {
			handle, gssLoadError = purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_LOCAL)
			if gssLoadError == nil {
				break
			}
		}
		if gssLoadError != nil {
			gssLoadError = fmt.Errorf("load system GSS-API library: %w", gssLoadError)
			return
		}
		functions := []struct {
			name     string
			function any
		}{
			{"gss_import_name", &gssLibrary.importName},
			{"gss_release_name", &gssLibrary.releaseName},
			{"gss_acquire_cred", &gssLibrary.acquireCred},
			{"gss_release_cred", &gssLibrary.releaseCred},
			{"gss_init_sec_context", &gssLibrary.initSecContext},
			{"gss_delete_sec_context", &gssLibrary.deleteSecContext},
			{"gss_release_buffer", &gssLibrary.releaseBuffer},
			{"gss_display_status", &gssLibrary.displayStatus},
		}
		for _, function := range functions {
			symbol, err := purego.Dlsym(handle, function.name)
			if err != nil {
				gssLoadError = fmt.Errorf("load %s: %w", function.name, err)
				purego.Dlclose(handle)
				return
			}
			purego.RegisterFunc(function.function, symbol)
		}
		// Keep the library loaded for the lifetime of all native contexts.
	})
	return &gssLibrary, gssLoadError
}

type gssClient struct {
	api     *gssAPI
	target  uintptr
	cred    uintptr
	context uintptr
}

func newClient(spn string) (Client, error) {
	api, err := loadGSS()
	if err != nil {
		return nil, err
	}
	c := &gssClient{api: api}
	nameType := &principalOID
	service, host, _ := strings.Cut(spn, "/")
	if !strings.Contains(host, "@") {
		// Let the system resolve the host's realm, which may differ from
		// the user's default realm for cross-realm proxies.
		spn = service + "@" + host
		nameType = &hostServiceOID
	}
	name := []byte(spn)
	input := gssBuffer{uintptr(len(name)), &name[0]}
	var minor uint32
	major := api.importName(&minor, &input, nameType, &c.target)
	runtime.KeepAlive(name)
	if major != 0 {
		err = api.statusError("import Kerberos SPN", major, minor)
		c.Close()
		return nil, err
	}
	// Restrict credentials to Kerberos, so SPNEGO cannot fall back to NTLM.
	// GSS_C_NO_NAME selects the current identity from the system credential store.
	mechs := gssOIDSet{1, &krb5OID}
	major = api.acquireCred(&minor, 0, 0, &mechs, 1, &c.cred, nil, nil)
	if major != 0 {
		err = api.statusError("acquire system Kerberos credentials", major, minor)
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *gssClient) Next(token []byte) ([]byte, bool, error) {
	if c.cred == 0 {
		return nil, false, errors.New("Kerberos context is closed")
	}
	var input, output gssBuffer
	if len(token) != 0 {
		input = gssBuffer{uintptr(len(token)), &token[0]}
	}
	var minor, flags uint32
	major := c.api.initSecContext(&minor, c.cred, &c.context, c.target, &spnegoOID,
		gssMutualFlag, 0, 0, &input, nil, &output, &flags, nil)
	runtime.KeepAlive(token)
	defer c.api.releaseBuffer(new(uint32), &output)
	if major != 0 && major != gssContinueNeeded {
		return nil, false, c.api.statusError("initialize Kerberos context", major, minor)
	}
	complete := major&gssContinueNeeded == 0
	if complete && flags&gssMutualFlag == 0 {
		return nil, false, errors.New("Kerberos mutual authentication was not established")
	}
	return append([]byte(nil), unsafe.Slice(output.value, output.length)...), complete, nil
}

func (c *gssClient) Close() error {
	var minor uint32
	var errs []error
	if c.context != 0 {
		if major := c.api.deleteSecContext(&minor, &c.context, nil); major != 0 {
			errs = append(errs, c.api.statusError("delete Kerberos context", major, minor))
		}
		c.context = 0
	}
	if c.cred != 0 {
		if major := c.api.releaseCred(&minor, &c.cred); major != 0 {
			errs = append(errs, c.api.statusError("release Kerberos credentials", major, minor))
		}
		c.cred = 0
	}
	if c.target != 0 {
		if major := c.api.releaseName(&minor, &c.target); major != 0 {
			errs = append(errs, c.api.statusError("release Kerberos name", major, minor))
		}
		c.target = 0
	}
	return errors.Join(errs...)
}

func (g *gssAPI) statusError(operation string, major, minor uint32) error {
	var messages []string
	for i, code := range []uint32{major, minor} {
		var messageContext uint32
		for n := 0; n < 8; n++ {
			var status uint32
			var output gssBuffer
			result := g.displayStatus(&status, code, int32(i+1), &krb5OID, &messageContext, &output)
			if result == 0 && output.length > 0 {
				messages = append(messages, string(unsafe.Slice(output.value, output.length)))
			}
			g.releaseBuffer(&status, &output)
			if result != 0 || messageContext == 0 {
				break
			}
		}
	}
	return fmt.Errorf("%s (GSS 0x%x/0x%x): %s", operation, major, minor, strings.Join(messages, "; "))
}
