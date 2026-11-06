package kerberos

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/alexbrainman/sspi"
)

// SEC_WINNT_AUTH_IDENTITY_EXW allows Negotiate to use the current identity
// while restricting its package list to Kerberos.
type authIdentityEx struct {
	Version        uint32
	Length         uint32
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
	PackageList    *uint16
	PackageLength  uint32
}

type sspiClient struct {
	cred     *sspi.Credentials
	context  *sspi.Context
	target   *uint16
	maxToken uint32
}

func CheckSupport() error { return nil }

func newClient(spn string) (Client, error) {
	target, err := syscall.UTF16PtrFromString(spn)
	if err != nil {
		return nil, err
	}
	info, err := sspi.QueryPackageInfo(sspi.NEGOSSP_NAME)
	if err != nil {
		return nil, fmt.Errorf("query SSPI Negotiate: %w", err)
	}
	packages, _ := syscall.UTF16PtrFromString("Kerberos")
	identity := authIdentityEx{
		Version:       0x200,
		Flags:         sspi.SEC_WINNT_AUTH_IDENTITY_UNICODE,
		PackageList:   packages,
		PackageLength: uint32(len("Kerberos")),
	}
	identity.Length = uint32(unsafe.Sizeof(identity))
	cred, err := sspi.AcquireCredentials("", sspi.NEGOSSP_NAME, sspi.SECPKG_CRED_OUTBOUND, (*byte)(unsafe.Pointer(&identity)))
	runtime.KeepAlive(identity)
	if err != nil {
		return nil, fmt.Errorf("acquire system Kerberos credentials: %w", err)
	}
	return &sspiClient{
		cred:     cred,
		context:  sspi.NewClientContext(cred, sspi.ISC_REQ_CONNECTION|sspi.ISC_REQ_MUTUAL_AUTH),
		target:   target,
		maxToken: info.MaxToken,
	}, nil
}

func (c *sspiClient) Next(token []byte) ([]byte, bool, error) {
	if c.cred == nil {
		return nil, false, errors.New("Kerberos context is closed")
	}
	var input *sspi.SecBufferDesc
	if len(token) > 0 {
		var buffer sspi.SecBuffer
		buffer.Set(sspi.SECBUFFER_TOKEN, token)
		input = sspi.NewSecBufferDesc([]sspi.SecBuffer{buffer})
	}
	output := make([]byte, c.maxToken)
	var buffer sspi.SecBuffer
	buffer.Set(sspi.SECBUFFER_TOKEN, output)
	desc := sspi.NewSecBufferDesc([]sspi.SecBuffer{buffer})
	status := c.context.Update(c.target, desc, input)
	complete := status == sspi.SEC_E_OK || status == sspi.SEC_I_COMPLETE_NEEDED
	switch status {
	case sspi.SEC_E_OK, sspi.SEC_I_CONTINUE_NEEDED:
	case sspi.SEC_I_COMPLETE_NEEDED, sspi.SEC_I_COMPLETE_AND_CONTINUE:
		if status = sspi.CompleteAuthToken(c.context.Handle, desc); status != sspi.SEC_E_OK {
			return nil, false, fmt.Errorf("complete SSPI token: %w", status)
		}
	default:
		return nil, false, fmt.Errorf("initialize SSPI Kerberos context: %w", status)
	}
	if complete {
		if err := c.context.VerifySelectiveFlags(sspi.ISC_REQ_MUTUAL_AUTH); err != nil {
			return nil, false, fmt.Errorf("verify Kerberos mutual authentication: %w", err)
		}
	}
	return output[:desc.Buffers.BufferSize], complete, nil
}

func (c *sspiClient) Close() error {
	var err error
	if c.context != nil && c.context.Handle != nil {
		err = c.context.Release()
	}
	c.context = nil
	if c.cred != nil {
		err = errors.Join(err, c.cred.Release())
		c.cred = nil
	}
	return err
}
