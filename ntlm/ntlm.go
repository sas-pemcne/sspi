// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

// Package ntlm provides access to the Microsoft NTLM SSP Package.
//
package ntlm

import (
	"errors"
	"syscall"
	"time"
	"unsafe"

	"github.com/alexbrainman/sspi"
)

// PackageInfo contains NTLM SSP package description.
var PackageInfo *sspi.PackageInfo

func init() {
	var err error
	PackageInfo, err = sspi.QueryPackageInfo(sspi.NTLMSP_NAME)
	if err != nil {
		panic("failed to fetch NTLM package info: " + err.Error())
	}
}

const _SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2

type _SEC_WINNT_AUTH_IDENTITY struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

func acquireCredentials(creduse uint32, ai *_SEC_WINNT_AUTH_IDENTITY) (*sspi.Credentials, error) {
	c, err := sspi.AcquireCredentials(sspi.NTLMSP_NAME, creduse, (*byte)(unsafe.Pointer(ai)))
	if err != nil {
		return nil, err
	}
	return c, nil
}

// AcquireCurrentUserCredentials acquires credentials of currently
// logged on user. These will be used by the client to authenticate
// itself to the server. It will also be used by the server
// to impersonate the user.
func AcquireCurrentUserCredentials() (*sspi.Credentials, error) {
	return acquireCredentials(sspi.SECPKG_CRED_OUTBOUND, nil)
}

// AcquireUserCredentials acquires credentials of user described by
// domain, username and password. These will be used by the client to
// authenticate itself to the server. It will also be used by the
// server to impersonate the user.
func AcquireUserCredentials(domain, username, password string) (*sspi.Credentials, error) {
	if len(domain) == 0 {
		return nil, errors.New("domain parameter cannot be empty")
	}
	if len(username) == 0 {
		return nil, errors.New("username parameter cannot be empty")
	}
	d, err := syscall.UTF16FromString(domain)
	if err != nil {
		return nil, err
	}
	u, err := syscall.UTF16FromString(username)
	if err != nil {
		return nil, err
	}
	var p []uint16
	var plen uint32
	if len(password) > 0 {
		p, err = syscall.UTF16FromString(password)
		if err != nil {
			return nil, err
		}
		plen = uint32(len(p) - 1) // do not count terminating 0
	}
	ai := _SEC_WINNT_AUTH_IDENTITY{
		User:           &u[0],
		UserLength:     uint32(len(u) - 1), // do not count terminating 0
		Domain:         &d[0],
		DomainLength:   uint32(len(d) - 1), // do not count terminating 0
		Password:       &p[0],
		PasswordLength: plen,
		Flags:          _SEC_WINNT_AUTH_IDENTITY_UNICODE,
	}
	return acquireCredentials(sspi.SECPKG_CRED_OUTBOUND, &ai)
}

// AcquireServerCredentials acquires server credentials that will
// be used to authenticate client.
func AcquireServerCredentials() (*sspi.Credentials, error) {
	return acquireCredentials(sspi.SECPKG_CRED_INBOUND, nil)
}

// ClientContext is used by the client to manage all steps of NTLM negotiation.
type ClientContext struct {
	sctxt *sspi.Context
}

// NewClientContext creates new client context. It uses client
// credentials cred generated by AcquireCurrentUserCredentials or
// AcquireUserCredentials and, if successful, outputs negotiate
// message. Negotiate message needs to be sent to the server to
// start NTLM negotiation sequence.
func NewClientContext(cred *sspi.Credentials) (*ClientContext, []byte, error) {
	negotiate := make([]byte, PackageInfo.MaxToken)
	c, authCompleted, n, err := sspi.NewClientContext(cred, sspi.ISC_REQ_CONNECTION, negotiate)
	if err != nil {
		return nil, nil, err
	}
	if authCompleted {
		c.Release()
		return nil, nil, errors.New("ntlm authentication should not be completed yet")
	}
	if n == 0 {
		c.Release()
		return nil, nil, errors.New("ntlm token should not be empty")
	}
	negotiate = negotiate[:n]
	return &ClientContext{sctxt: c}, negotiate, nil
}

// Release free up resources associated with client context c.
func (c *ClientContext) Release() error {
	return c.sctxt.Release()
}

// Expiry returns c expiry time.
func (c *ClientContext) Expiry() time.Time {
	return c.sctxt.Expiry()
}

// Update completes client part of NTLM negotiation c. It uses
// challenge message received from the server, and generates
// authenticate message to be returned to the server.
func (c *ClientContext) Update(challenge []byte) ([]byte, error) {
	authenticate := make([]byte, PackageInfo.MaxToken)
	authCompleted, n, err := c.sctxt.Update(authenticate, challenge)
	if err != nil {
		return nil, err
	}
	if !authCompleted {
		return nil, errors.New("ntlm authentication should be completed now")
	}
	if n == 0 {
		return nil, errors.New("ntlm token should not be empty")
	}
	authenticate = authenticate[:n]
	return authenticate, nil
}

// ServerContext is used by the server to manage all steps of NTLM
// negotiation. Once authentication is completed the context can be
// used to impersonate client.
type ServerContext struct {
	sctxt *sspi.Context
}

// NewServerContext creates new server context. It uses server
// credentials created by AcquireServerCredentials and client
// negotiate message and, if successful, outputs challenge message.
// Challenge message needs to be sent to the client to continue
// NTLM negotiation sequence.
func NewServerContext(cred *sspi.Credentials, negotiate []byte) (*ServerContext, []byte, error) {
	challenge := make([]byte, PackageInfo.MaxToken)
	c, authCompleted, n, err := sspi.NewServerContext(cred, sspi.ISC_REQ_CONNECTION, challenge, negotiate)
	if err != nil {
		return nil, nil, err
	}
	if authCompleted {
		c.Release()
		return nil, nil, errors.New("ntlm authentication should not be completed yet")
	}
	if n == 0 {
		c.Release()
		return nil, nil, errors.New("ntlm token should not be empty")
	}
	challenge = challenge[:n]
	return &ServerContext{sctxt: c}, challenge, nil
}

// Release free up resources associated with server context c.
func (c *ServerContext) Release() error {
	return c.sctxt.Release()
}

// Expiry returns c expiry time.
func (c *ServerContext) Expiry() time.Time {
	return c.sctxt.Expiry()
}

// Update completes server part of NTLM negotiation c. It uses
// authenticate message received from the client.
func (c *ServerContext) Update(authenticate []byte) error {
	authCompleted, n, err := c.sctxt.Update(nil, authenticate)
	if err != nil {
		return err
	}
	if !authCompleted {
		return errors.New("ntlm authentication should be completed now")
	}
	if n != 0 {
		return errors.New("ntlm token should be empty now")
	}
	return nil
}

// ImpersonateUser changes current OS thread user. New user is
// the user as specified by client credentials.
func (c *ServerContext) ImpersonateUser() error {
	return c.sctxt.ImpersonateUser()
}

// RevertToSelf stops impersonation. It changes current OS thread
// user to what it was before ImpersonateUser was executed.
func (c *ServerContext) RevertToSelf() error {
	return c.sctxt.RevertToSelf()
}
