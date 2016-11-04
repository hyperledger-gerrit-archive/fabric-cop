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

package main

import (
	"github.com/cloudflare/cfssl/log"
	"os"
	"testing"
	"time"
)

const (
	CERT string = "../../testdata/cop-cert.pem"
	KEY  string = "../../testdata/cop-key.pem"
	CFG  string = "../../testdata/cop.json"
	CSR  string = "../../testdata/csr.json"
	REG  string = "../../testdata/registerRequest.json"
	CSRJSON string = "../../testdata/csr_tcdsa.json"
)

var serverStarted bool
var serverExitCode = 0
var initStarted bool
// Test the server start command
func TestStartServer(t *testing.T) {
	rtn := startServer()
	if rtn != 0 {
		t.Errorf("Failed to start server with return code: %d", rtn)
		t.FailNow()
	}
}

// TODO: Add back enroll test
// func TestEnroll(t *testing.T) {
// 	rtn := enroll("admin", "adminpw")
// 	if rtn != 0 {
// 		t.Errorf("Failed to enroll with return code: %d", rtn)
// 	}
// }

//TODO: Add back register test
//func TestRegister(t *testing.T) {
//	rtn := register(REG)
//	if rtn != 0 {
//		t.Errorf("Failed to register with return code: %d", rtn)
//	}
//}

func startServer() int {
	if !serverStarted {
		serverStarted = true
		log.Debug("starting COP server ...")
		go runServer()
		time.Sleep(3 * time.Second)
		log.Debug("COP server started")
	} else {
		log.Debug("COP server already started")
	}
	return serverExitCode
}

func runServer() {
	os.Setenv("COP_DEBUG", "true")
	serverExitCode = COPMain([]string{"cop", "server", "start", "-ca", CERT, "-ca-key", KEY, "-config", CFG})
}

func enroll(user, pass string) int {
	log.Debug("enrolling user '%s' with password '%s' ...\n", user, pass)
	rtn := COPMain([]string{"cop", "client", "enroll", user, pass, CSR, "http://localhost:8888", "loglevel=0"})
	log.Debug("enroll result is '%d'\n", rtn)
	return rtn
}

func register(file string) int {
	log.Debug("register file '%s' ...\n", file)
	rtn := COPMain([]string{"cop", "client", "register", file, "keith", "http://localhost:8888", "loglevel=0"})
	log.Debug("register result is '%d'\n", rtn)
	return rtn
}

func TestServerInit(t *testing.T) {
	rtn := initServer()
	if rtn != 0 {
		t.Errorf("Failed to invoke initServer with return code: %d", rtn)
		t.FailNow()
	}
}
func initServer() int {
	if !initStarted {
		initStarted = true
		log.Debug("Generating private key and self-signed certiticate for COP server")
		go genCertAndKey()
		time.Sleep(3 * time.Second)
		log.Debug("Writing server-cert.pem and server-key.pem to $COP_HOME directory")
	} else {
		log.Debug("Server init already running")
	}
	return serverExitCode
}

func genCertAndKey() {
	os.Setenv("COP_DEBUG", "true")
	serverExitCode = COPMain([]string{"cop", "server", "init", CSRJSON})
}
