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
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/cli/serve"
)

const (
	ENROLLDIR    = "/tmp/enroll"
	ENROLLCONFIG = "../../testdata/testConfig.json"
	CSR          = "../../testdata/csr.csr"
)

func TestEnroll(t *testing.T) {
	startServer()

	e := NewEnrollUser()
	testUnregisteredUser(e, t)
	testIncorrectToken(e, t)
	testEnrollingUser(e, t)

	os.RemoveAll(ENROLLDIR)

}

func testUnregisteredUser(e *Enroll, t *testing.T) {
	_, err := e.Enroll("Unregistered", []byte("test"), nil)
	if err == nil {
		t.Error("Unregistered user should not be allowed to enroll, should have failed")
	}
}

func testIncorrectToken(e *Enroll, t *testing.T) {
	_, err := e.Enroll("notadmin", []byte("pass1"), nil)
	if err == nil {
		t.Error("Incorrect token should not be allowed to enroll, should have failed")
	}
}

func testEnrollingUser(e *Enroll, t *testing.T) {
	csrPEM, _ := ioutil.ReadFile(CSR)
	_, err := e.Enroll("testUser", []byte("user1"), csrPEM)
	if err != nil {
		t.Error("Failed to enroll user")
	}
}

func enrollEndpoint() {
	// Add the "enroll" route/endpoint
	serve.SetEndpoint("enroll", NewEnrollHandler)
}
