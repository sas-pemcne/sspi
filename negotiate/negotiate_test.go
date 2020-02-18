// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package negotiate_test

import (
	"bytes"
	"crypto/rand"
	"flag"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
)

var (
	testDomain   = flag.String("domain", "", "domain parameter for TestAcquireUserCredentials")
	testUsername = flag.String("username", "", "username parameter for TestAcquireUserCredentials")
	testPassword = flag.String("password", "", "password parameter for TestAcquireUserCredentials")
)

func TestPackageInfo(t *testing.T) {
	if negotiate.PackageInfo.Name != "Negotiate" {
		t.Fatalf(`invalid Negotiate package name of %q, "Negotiate" is expected.`, negotiate.PackageInfo.Name)
	}
}

func testContextExpiry(t *testing.T, name string, c interface {
	Expiry() time.Time
}) {
	validFor := c.Expiry().Sub(time.Now())
	if validFor < time.Hour {
		t.Errorf("%v expires in %v, more than 1 hour expected", name, validFor)
	}
	if validFor > 10*24*time.Hour {
		t.Errorf("%v expires in %v, less than 10 days expected", name, validFor)
	}
}

func testNegotiate(t *testing.T, clientCred *sspi.Credentials, SPN string) {
	if len(SPN) == 0 {
		t.Log("testing with blank SPN")
	} else {
		t.Logf("testing with SPN=%s", SPN)
	}

	serverCred, err := negotiate.AcquireServerCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	defer serverCred.Release()

	client, toServerToken, err := negotiate.NewClientContext(clientCred, SPN, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Release()

	if len(toServerToken) == 0 {
		t.Fatal("token for server cannot be empty")
	}
	t.Logf("sent %d bytes to server", len(toServerToken))

	testContextExpiry(t, "client security context", client)

	server, serverDone, toClientToken, err := negotiate.NewServerContext(serverCred, toServerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Release()

	testContextExpiry(t, "server security context", server)

	var clientDone bool
	for {
		if len(toClientToken) == 0 {
			break
		}
		t.Logf("sent %d bytes to client", len(toClientToken))
		clientDone, toServerToken, err = client.Update(toClientToken)
		if err != nil {
			t.Fatal(err)
		}
		if len(toServerToken) == 0 {
			break
		}
		t.Logf("sent %d bytes to server", len(toServerToken))
		serverDone, toClientToken, err = server.Update(toServerToken)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !clientDone {
		t.Fatal("client authentication should be completed now")
	}
	if !serverDone {
		t.Fatal("server authentication should be completed now")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err = server.ImpersonateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer server.RevertToSelf()

	_, err = user.Current()
	if err != nil {
		t.Fatal(err)
	}
}

func TestNegotiate(t *testing.T) {
	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	defer cred.Release()

	testNegotiate(t, cred, "")

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	testNegotiate(t, cred, "HOST/"+strings.ToUpper(hostname))

	testNegotiate(t, cred, "HOST/127.0.0.1")
}

func TestNegotiateFailure(t *testing.T) {
	clientCred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	defer clientCred.Release()

	serverCred, err := negotiate.AcquireServerCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	defer serverCred.Release()

	client, toServerToken, err := negotiate.NewClientContext(clientCred, "HOST/UNKNOWN_HOST_NAME", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Release()

	if len(toServerToken) == 0 {
		t.Fatal("token for server cannot be empty")
	}
	t.Logf("sent %d bytes to server", len(toServerToken))

	server, serverDone, toClientToken, err := negotiate.NewServerContext(serverCred, toServerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Release()

	for {
		var clientDone bool
		if len(toClientToken) == 0 {
			t.Fatal("token for client cannot be empty")
		}
		t.Logf("sent %d bytes to client", len(toClientToken))
		clientDone, toServerToken, err = client.Update(toClientToken)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("clientDone=%v serverDone=%v", clientDone, serverDone)
		if clientDone {
			//			t.Fatal("client authentication cannot be completed")
		}
		if len(toServerToken) == 0 {
			t.Fatal("token for server cannot be empty")
		}
		t.Logf("sent %d bytes to server", len(toServerToken))
		serverDone, toClientToken, err = server.Update(toServerToken)
		if err != nil {
			if err == sspi.SEC_E_LOGON_DENIED {
				return
			}
			t.Fatalf("unexpected failure 0x%x: %v", uintptr(err.(syscall.Errno)), err)
		}
		t.Logf("clientDone=%v serverDone=%v", clientDone, serverDone)
		if serverDone {
			t.Fatal("server authentication cannot be completed")
		}
	}
}

func TestAcquireUserCredentials(t *testing.T) {
	if len(*testDomain) == 0 {
		t.Skip("Skipping due to empty \"domain\" parameter")
	}
	if len(*testUsername) == 0 {
		t.Skip("Skipping due to empty \"username\" parameter")
	}
	if len(*testPassword) == 0 {
		t.Skip("Skipping due to empty \"password\" parameter")
	}
	cred, err := negotiate.AcquireUserCredentials(*testDomain, *testUsername, *testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer cred.Release()

	testNegotiate(t, cred, "")
}

func TestSignatureEncryption(t *testing.T) {
	clientCred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	defer clientCred.Release()

	serverCred, err := negotiate.AcquireServerCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	defer serverCred.Release()

	client, toServerToken, err := negotiate.NewClientContext(clientCred, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Release()

	if len(toServerToken) == 0 {
		t.Fatal("token for server cannot be empty")
	}

	server, serverDone, toClientToken, err := negotiate.NewServerContext(serverCred, toServerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Release()

	var clientDone bool
	for {
		if len(toClientToken) == 0 {
			break
		}
		clientDone, toServerToken, err = client.Update(toClientToken)
		if err != nil {
			t.Fatal(err)
		}
		if len(toServerToken) == 0 {
			break
		}
		serverDone, toClientToken, err = server.Update(toServerToken)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !clientDone {
		t.Fatal("client authentication should be completed now")
	}
	if !serverDone {
		t.Fatal("server authentication should be completed now")
	}

	clientMsg := make([]byte, 10)
	_, err = rand.Read(clientMsg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("clientMsg=%v", clientMsg)

	clientSig, err := client.MakeSignature(clientMsg, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("clientSig=%v", clientSig)

	_, err = server.VerifySignature(clientMsg, clientSig, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("server verified client signature")

	var clientQop uint32
	clientCrypt, err := client.EncryptMessage(copyArray(clientMsg), clientQop, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("clientMsg=%v,clientCrypt=%v", clientMsg, clientCrypt)

	qop, m2, err := server.DecryptMessage(clientCrypt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if qop != clientQop {
		t.Fatalf("Wrong value %d for qop", qop)
	}
	if !bytes.Equal(clientMsg, m2) {
		t.Fatalf("Wrong value %v for message decrypted by server (expected %v)", m2, clientMsg)
	}
	t.Logf("server decrypted client message")

	serverMsg := make([]byte, 10)
	_, err = rand.Read(serverMsg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("serverMsg=%v", serverMsg)

	serverSig, err := server.MakeSignature(serverMsg, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("serverSig=%v", serverSig)

	_, err = client.VerifySignature(serverMsg, serverSig, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client verified server signature")
}

func TestFlagVerification(t *testing.T) {
	clientCred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	defer clientCred.Release()

	serverCred, err := negotiate.AcquireServerCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	defer serverCred.Release()

	const desiredFlags = sspi.ISC_REQ_CONFIDENTIALITY |
		sspi.ISC_REQ_INTEGRITY |
		sspi.ISC_REQ_MUTUAL_AUTH |
		sspi.ISC_REQ_REPLAY_DETECT |
		sspi.ISC_REQ_SEQUENCE_DETECT

	client, toServerToken, err := negotiate.NewClientContextWithFlags(clientCred, "", desiredFlags, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Release()

	if len(toServerToken) == 0 {
		t.Fatal("token for server cannot be empty")
	}

	server, serverDone, toClientToken, err := negotiate.NewServerContext(serverCred, toServerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Release()

	if len(toClientToken) == 0 {
		t.Fatal("token for client cannot be empty")
	}

	errMsg := "sspi: invalid flags check: desired=100000000 requested=10000000000011110 missing=100000000 extra=10000000000011110"

	var clientDone bool
	for {
		if len(toClientToken) == 0 {
			break
		}
		clientDone, toServerToken, err = client.Update(toClientToken)
		if err != nil {
			t.Fatal(err)
		}

		// verify all flags
		if err := client.VerifyFlags(); err != nil {
			t.Fatal(err)
		}
		// verify a subset of flags
		if err := client.VerifySelectiveFlags(sspi.ISC_REQ_MUTUAL_AUTH); err != nil {
			t.Fatal(err)
		}
		// try to verify a flag that was not initially requested
		if err := client.VerifySelectiveFlags(sspi.ISC_REQ_ALLOCATE_MEMORY); err == nil || err.Error() != errMsg {
			t.Fatalf("wrong error found: %v", err)
		}

		if len(toServerToken) == 0 {
			break
		}
		serverDone, toClientToken, err = server.Update(toServerToken)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !clientDone {
		t.Fatal("client authentication should be completed now")
	}
	if !serverDone {
		t.Fatal("server authentication should be completed now")
	}
}

func TestChannelBindings(t *testing.T) {
	// Just use a random byte array for a sample
	sampleCert := []byte{0, 130, 47, 116, 219, 9, 243, 115, 113, 252, 92, 2, 175, 213, 115, 140, 21, 96, 52, 94, 27, 64}
	expected := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0, 0, 0, 32, 0, 0, 0,
	                   116, 108, 115, 45, 115, 101, 114, 118, 101, 114, 45, 101, 110, 100, 45, 112, 111, 105, 110, 116,
	                   58, 35, 214, 154, 220, 64, 185, 169, 240, 127, 2, 198, 159, 121, 64, 29, 188, 207, 100, 40, 250,
	                   104, 33, 47, 168, 133, 56, 71, 98, 56, 200, 177, 0}
	channelBindings, err := negotiate.GenerateChannelBindings(sampleCert)
	if err != nil {
		t.Fatal(err)
	}
	bindingBuffer := channelBindings.Bytes()
	if !bytes.Equal(bindingBuffer, expected) {
		t.Fatalf("Incorrect channel bindings bytes, expecting '%q' but got '%q'", expected, bindingBuffer)
	}
}

func copyArray(a []byte) []byte {
	b := make([]byte, len(a))
	copy(b, a)
	return b
}
