//go:build (darwin || (linux && with_gssapi)) && !android && !ios && (amd64 || arm64)

package kerberos

import (
	"os"
	"runtime"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
)

func TestGSSNativeBindings(t *testing.T) {
	api, err := loadGSS()
	if err != nil {
		t.Fatal(err)
	}
	name := []byte("HTTP/proxy.example@EXAMPLE.COM")
	input := gssBuffer{uintptr(len(name)), &name[0]}
	var minor uint32
	var target uintptr
	if major := api.importName(&minor, &input, &principalOID, &target); major != 0 {
		t.Fatal(api.statusError("import test name", major, minor))
	}
	runtime.KeepAlive(name)
	c := &gssClient{api: api, target: target}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Next(nil); err == nil {
		t.Fatal("closed context accepted a token")
	}
	// Exercise native status buffers without reading the user's credentials.
	if err := api.statusError("test", 7<<16, 0); err == nil {
		t.Fatal("missing GSS error")
	}
}

// Run against an isolated realm with a valid default initiator credential and
// a service keytab in KRB5_KTNAME. The normal test suite does not use user tickets.
func TestGSSSystemIdentityIntegration(t *testing.T) {
	spn := os.Getenv("MIHOMO_KERBEROS_TEST_SPN")
	if spn == "" {
		t.Skip("set MIHOMO_KERBEROS_TEST_SPN for native Kerberos integration")
	}
	api, err := loadGSS()
	if err != nil {
		t.Fatal(err)
	}
	library := "libgssapi_krb5.so.2"
	if runtime.GOOS == "darwin" {
		library = "/System/Library/Frameworks/GSS.framework/GSS"
	}
	handle, err := purego.Dlopen(library, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	defer purego.Dlclose(handle)
	var accept func(*uint32, *uintptr, uintptr, *gssBuffer, uintptr, *uintptr, *uintptr, *gssBuffer, *uint32, *uint32, *uintptr) uint32
	purego.RegisterLibFunc(&accept, handle, "gss_accept_sec_context")
	var minor uint32
	var serverCred, serverContext uintptr
	if major := api.acquireCred(&minor, 0, 0, nil, 2, &serverCred, nil, nil); major != 0 {
		t.Fatal(api.statusError("acquire test service credential", major, minor))
	}
	defer api.releaseCred(&minor, &serverCred)
	defer func() {
		if serverContext != 0 {
			api.deleteSecContext(&minor, &serverContext, nil)
		}
	}()
	client, err := NewClient(spn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	token, complete, err := client.Next(nil)
	if err != nil {
		t.Fatal(err)
	}
	if complete || len(token) == 0 {
		t.Fatal("initial token must require mutual authentication")
	}
	for round := 0; round < 8; round++ {
		input := gssBuffer{uintptr(len(token)), &token[0]}
		var output gssBuffer
		major := accept(&minor, &serverContext, serverCred, &input, 0, nil, nil, &output, nil, nil, nil)
		runtime.KeepAlive(token)
		if major != 0 && major != gssContinueNeeded {
			api.releaseBuffer(new(uint32), &output)
			t.Fatal(api.statusError("accept client token", major, minor))
		}
		serverToken := append([]byte(nil), unsafe.Slice(output.value, output.length)...)
		api.releaseBuffer(new(uint32), &output)
		token, complete, err = client.Next(serverToken)
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			if major != 0 || len(token) != 0 {
				t.Fatal("asymmetric completion")
			}
			return
		}
		if len(token) == 0 {
			t.Fatal("empty continuation token")
		}
	}
	t.Fatal("authentication did not complete")
}
