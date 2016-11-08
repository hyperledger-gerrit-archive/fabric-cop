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

package client

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/hyperledger/fabric-cop/cli/server"
)

var serverStarted bool
var serverExitCode = 0

func runServer() {
	os.Setenv("COP_DEBUG", "true")
	server.Start("../../testdata")
}

func startServer() int {
	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		os.Setenv("COP_HOME", "../../testdata")
		go runServer()
		time.Sleep(3 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
	return serverExitCode
}

func TestRegisterCLI(t *testing.T) {
	startServer()
	time.Sleep(3 * time.Second)

	os.Setenv("COP_HOME", "../../testdata")
	c := new(cli.Config)

	args := []string{"../../testdata/registerRequest.json", "http://localhost:8888"}

	err := registerMain(args, *c)
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

}

func TestRegisterNotEnoughArgs(t *testing.T) {
	c := new(cli.Config)

	args := []string{"../../testdata/registerRequest.json"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should have failed, not enough arguments provided")
	}

}

func TestRegisterNoJSON(t *testing.T) {
	c := new(cli.Config)

	args := []string{"", "admin", "http://localhost:8888"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should result in failure if registration json file not specificied, error: ", err)
	}

}

func TestRegisterMissingRegistrar(t *testing.T) {
	c := new(cli.Config)

	// os.Setenv("COP_HOME", "/tmp")
	args := []string{"", "", "http://localhost:8888"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should result in failure if no registrar identity exists")
	}

}

func TestEnrollCLINotEnoughArgs(t *testing.T) {

	c := new(cli.Config)

	args := []string{"testUser"}

	err := enrollMain(args, *c)
	if err == nil {
		t.Error("Should have failed, not enough argument provided")
	}

}

func TestEnrollCLI(t *testing.T) {

	c := new(cli.Config)

	args := []string{"testUser", "user1", "http://localhost:8888"}

	err := enrollMain(args, *c)
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

}

func TestEnrollCLIWithCSR(t *testing.T) {

	c := new(cli.Config)

	args := []string{"testUser2", "user2", "http://localhost:8888", "../../testdata/csr.json"}

	err := enrollMain(args, *c)
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

	os.Remove("../../testdata/eca.db")
}