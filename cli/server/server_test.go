/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	factory "github.com/hyperledger/fabric-cop"
	"github.com/hyperledger/fabric-cop/cli/server/dbutil"
	"github.com/hyperledger/fabric-cop/cli/server/ldap"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/lib"
	"github.com/hyperledger/fabric-cop/util"
)

const (
	CFGFile         = "testconfig2.json"
	ClientTLSConfig = "cop_client.json"
)

var serverStarted bool
var serverExitCode = 0
var dir string

func createServer() *Server {
	s := new(Server)
	return s
}

func startServer() {
	var err error

	dir, err = ioutil.TempDir("", "home")
	if err != nil {
		fmt.Printf("Failed to create temp directory [error: %s]", err)
		return
	}

	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		os.Setenv("COP_DEBUG", "true")
		os.Setenv("COP_HOME", dir)
		go runServer()
		time.Sleep(10 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
}

func runServer() {
	Start("../../testdata", CFGFile)
}

func TestPostgresFail(t *testing.T) {
	_, _, err := dbutil.NewUserRegistryPostgres("dbname=cop sslmode=disable", nil)
	if err == nil {
		t.Error("No postgres server running, this should have failed")
	}
}

func TestRegisterUser(t *testing.T) {
	startServer()
	clientConfig := filepath.Join(dir, ClientTLSConfig)
	os.Link("../../testdata/cop_client2.json", clientConfig)

	copServer := `{"serverURL":"https://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	enrollReq := &idp.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}

	ID, err := c.Enroll(enrollReq)
	if err != nil {
		t.Error("Enroll of user 'admin' with password 'adminpw' failed")
		return
	}

	err = ID.Store()
	if err != nil {
		t.Errorf("Failed to store enrollment information: %s", err)
		return
	}

	regReq := &idp.RegistrationRequest{
		Name:  "TestUser1",
		Type:  "Client",
		Group: "bank_a",
	}

	id, _ := factory.NewIdentity()
	path := filepath.Join(dir, "client.json")
	identity, err := ioutil.ReadFile(path)
	if err != nil {
		t.Error(err)
	}
	util.Unmarshal(identity, id, "identity")

	regReq.Registrar = id

	_, err = c.Register(regReq)
	if err != nil {
		t.Error(err)
	}
}

func TestMisc(t *testing.T) {
	copServer := `{"serverURL":"https://localhost:8888"}`
	c, err := lib.NewClient(copServer)
	if err != nil {
		t.Errorf("TestMisc.NewClient failed: %s", err)
		return
	}
	id, err := c.LoadMyIdentity()
	if err != nil {
		t.Errorf("TestMisc.LoadMyIdentity failed: %s", err)
		return
	}
	// Test static
	_, err = id.Post("/", nil)
	if err != nil {
		t.Errorf("TestMisc.Static failed: %s", err)
	}
	testStatic(id, t)
	testWithoutAuthHdr(c, t)
}

func TestEnrollUser(t *testing.T) {
	copServer := `{"serverURL":"https://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	id, err := c.Enroll(req)
	if err != nil {
		t.Error("enroll of user 'testUser' with password 'user1' failed")
		return
	}

	reenrollReq := &idp.ReenrollmentRequest{
		ID: id,
	}

	_, err = c.Reenroll(reenrollReq)
	if err != nil {
		t.Error("reenroll of user 'testUser' failed")
		return
	}

	err = id.RevokeSelf()
	if err == nil {
		t.Error("revoke of user 'testUser' passed but should have failed since has no 'hf.Revoker' attribute")
	}

}

func TestRevoke(t *testing.T) {
	copServer := `{"serverURL":"https://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "admin2",
		Secret: "adminpw2",
	}

	id, err := c.Enroll(req)
	if err != nil {
		t.Error("enroll of user 'admin2' with password 'adminpw2' failed")
		return
	}

	err = id.Revoke(&idp.RevocationRequest{})
	if err == nil {
		t.Error("Revoke with no args should have failed but did not")
	}

	err = id.Revoke(&idp.RevocationRequest{Serial: "foo", AKI: "bar"})
	if err == nil {
		t.Error("Revoke with bogus serial and AKI should have failed but did not")
	}

	err = id.Revoke(&idp.RevocationRequest{Name: "foo"})
	if err == nil {
		t.Error("Revoke with bogus name should have failed but did not")
	}

	err = id.RevokeSelf()
	if err != nil {
		t.Error("revoke of user 'admin2' failed")
		return
	}

	err = id.RevokeSelf()
	if err == nil {
		t.Error("RevokeSelf twice should have failed but did not")
	}
}

func TestGetTCerts(t *testing.T) {
	fmt.Println("AVANI")
	copServer := `{"serverURL":"https://localhost:8888"}`
	c, err := lib.NewClient(copServer)
	if err != nil {
		t.Errorf("TestGetTCerts.NewClient failed: %s", err)
		return
	}
	id, err := c.LoadMyIdentity()
	if err != nil {
		t.Errorf("TestGetTCerts.LoadMyIdentity failed: %s", err)
		return
	}
	// Getting TCerts
	_, err = id.GetPrivateSigners(&idp.GetPrivateSignersRequest{
		Count: 1,
	})
	if err != nil {
		t.Errorf("GetPrivateSigners failed: %s", err)
	}

	//Getting TCerts for option 2
	pubKeySigBatch, error := GetTemporalBatch(&idp.GetPrivateSignersRequest{
		Count: 1,
	}, 1)
	if error != nil {
		t.Logf("Public Key generation failed : [%v]", error)
	}

	_, tcertError := id.GetPrivateSigners(&idp.GetPrivateSignersRequest{
		Count:          1,
		SignatureBatch: pubKeySigBatch,
	})
	if tcertError != nil {
		t.Errorf("GetPrivateSigners for Client Generated Request failed: %s", err)
	}

}

func TestMaxEnrollment(t *testing.T) {
	CFG.UsrReg.MaxEnrollments = 2

	copServer := `{"serverURL":"https://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	regReq := &idp.RegistrationRequest{
		Name:  "MaxTestUser",
		Type:  "Client",
		Group: "bank_a",
	}

	id, _ := factory.NewIdentity()
	path := filepath.Join(dir, "client.json")
	identity, err := ioutil.ReadFile(path)
	if err != nil {
		t.Error(err)
	}
	util.Unmarshal(identity, id, "identity")

	regReq.Registrar = id

	resp, err := c.Register(regReq)
	if err != nil {
		t.Error(err)
	}

	secretBytes, err := base64.StdEncoding.DecodeString(resp.Secret)
	if err != nil {
		t.Fatalf("Failed decoding secret: %s", err)
	}

	enrollReq := &idp.EnrollmentRequest{
		Name:   "MaxTestUser",
		Secret: string(secretBytes),
	}

	_, err = c.Enroll(enrollReq)
	if err != nil {
		t.Error("Enroll of user 'MaxTestUser' failed")
		return
	}

	_, err = c.Enroll(enrollReq)
	if err != nil {
		t.Error("Enroll of user 'MaxTestUser' failed")
		return
	}

	_, err = c.Enroll(enrollReq)
	if err == nil {
		t.Error("Enroll of user should have failed, max enrollment reached")
		return
	}

}

func TestEnroll(t *testing.T) {
	e := NewEnrollUser()

	testUnregisteredUser(e, t)
	testIncorrectToken(e, t)
	testEnrollingUser(e, t)
}

func testUnregisteredUser(e *Enroll, t *testing.T) {
	copServer := `{"serverURL":"https://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "Unregistered",
		Secret: "test",
	}

	_, err := c.Enroll(req)

	if err == nil {
		t.Error("Unregistered user should not be allowed to enroll, should have failed")
	}
}

func testIncorrectToken(e *Enroll, t *testing.T) {
	copServer := `{"serverURL":"https://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "notadmin",
		Secret: "pass1",
	}

	_, err := c.Enroll(req)

	if err == nil {
		t.Error("Incorrect token should not be allowed to enroll, should have failed")
	}
}

func testEnrollingUser(e *Enroll, t *testing.T) {
	copServer := `{"serverURL":"https://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "testUser2",
		Secret: "user2",
	}

	_, err := c.Enroll(req)

	if err != nil {
		t.Error("Enroll of user 'testUser2' with password 'user2' failed")
		return
	}

}

func TestGetCertificatesByID(t *testing.T) {
	certRecord, err := certDBAccessor.GetCertificatesByID("testUser2")
	if err != nil {
		t.Errorf("Error occured while getting certificate for id 'testUser2', [error: %s]", err)
	}
	if len(certRecord) == 0 {
		t.Error("Failed to get certificate by user id, for user: 'testUser2'")
	}
}

func TestRevokeCertificatesByID(t *testing.T) {
	_, err := certDBAccessor.RevokeCertificatesByID("testUser2", 1)
	if err != nil {
		t.Errorf("Error occured while revoking certificate for id 'testUser2', [error: %s]", err)
	}
}

func TestGetField(t *testing.T) {
	_, err := userRegistry.GetField("testUser2", 5)
	if err == nil {
		t.Errorf("Error should occured while getting unsupported field, [error: %s]", err)
	}
}

func TestUpdateField(t *testing.T) {
	err := userRegistry.UpdateField("testUser2", state, 5)
	if err != nil {
		t.Errorf("Error occured while updating state field for id 'testUser2', [error: %s]", err)
	}
}

func TestUserRegistry(t *testing.T) {

	err := InitUserRegistry(&Config{DBdriver: "postgres", DataSource: "dbname=cop sslmode=disable"})
	if err == nil {
		t.Error("Trying to create a postgres registry should have failed")
	}

	err = InitUserRegistry(&Config{DBdriver: "mysql", DataSource: "root:root@tcp(localhost:3306)/cop?parseTime=true"})
	if err == nil {
		t.Error("Trying to create a mysql registry should have failed")
	}

	err = InitUserRegistry(&Config{DBdriver: "foo", DataSource: "boo"})
	if err == nil {
		t.Error("Trying to create a unsupported database type should have failed")
	}

	err = InitUserRegistry(&Config{LDAP: &ldap.Config{}})
	if err == nil {
		t.Error("Trying to LDAP with no URL; it should have failed but passed")
	}

}

func TestCreateHome(t *testing.T) {
	s := createServer()
	t.Log("Test Creating Home Directory")
	os.Unsetenv("COP_HOME")
	tempDir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Errorf("Failed to create temp directory [error: %s]", err)
	}
	os.Setenv("HOME", tempDir)

	_, err = s.CreateHome()
	if err != nil {
		t.Errorf("Failed to create home directory, error: %s", err)
	}

	if _, err = os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			t.Error("Failed to create home directory")
		}
	}

}

func TestLast(t *testing.T) {
	// Cleanup
	os.RemoveAll(dir)
}

func testStatic(id *lib.Identity, t *testing.T) {
	_, err := id.Post("/", nil)
	if err != nil {
		t.Errorf("testStatic failed: %s", err)
	}
}

func testWithoutAuthHdr(c *lib.Client, t *testing.T) {
	req, err := c.NewPost("enroll", nil)
	if err != nil {
		t.Errorf("testWithAuthHdr.NewPost failed: %s", err)
		return
	}
	_, err = c.SendPost(req)
	if err == nil {
		t.Error("testWithAuthHdr.SendPost should have failed but passed")
	}
}

func GetTemporalBatch(batchRequest *idp.GetPrivateSignersRequest, count int) ([]idp.KeySigPair, error) {

	var priv *ecdsa.PrivateKey
	var err error
	var ecSignaure idp.ECSignature
	var signature idp.Signature
	var tempCrypto idp.KeySigPair

	//Generate Payload based on the batch Request
	batchRaw := fmt.Sprintf("%v", batchRequest)
	raw := []byte((batchRaw))

	//payload := batchRequest.Payload

	var set []idp.KeySigPair
	for i := 0; i < count; i++ {
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pubASN1, marshallError := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if marshallError != nil {
			return nil, marshallError
		}
		r, s, signError := ECDSASignDirect(priv, raw, "SHA2_256")
		if signError != nil {
			return nil, signError
		}
		ecSignaure = idp.ECSignature{R: r, S: s}
		signature = idp.Signature{
			HashAlgo:    "SHA2_256",
			ECSignature: ecSignaure,
		}

		tempCrypto = idp.KeySigPair{Payload: raw, PublicKey: pubASN1, Signature: signature}

		set = append(set, tempCrypto)

	}

	return set, nil
}

func ECDSASignDirect(signKey interface{}, msg []byte, hashAlgo string) (*big.Int, *big.Int, error) {
	temp := signKey.(*ecdsa.PrivateKey)

	var hash hash.Hash

	switch hashAlgo {
	case "SHA2_256":
		hash = sha256.New()
	case "SHA2_384":
		hash = sha512.New384()
	case "SHA3_256":
		hash = sha3.New256()
	case "SHA3_384":
		hash = sha3.New384()
	default:
		return nil, nil, errors.New("Hash Algorithm not recognized")
	}
	hash.Write(msg)
	h := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, temp, h)
	if err != nil {
		return nil, nil, err
	}
	return r, s, nil
}
