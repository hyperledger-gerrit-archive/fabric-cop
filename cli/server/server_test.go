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
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	factory "github.com/hyperledger/fabric-cop"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

const (
	homeDir    = "/tmp/home"
	dataSource = "/tmp/home/server.db"
	configFile = "../../testdata/cop.json"
	CERT       = "../../testdata/ec.pem"
	KEY        = "../../testdata/ec-key.pem"
	CONFIG     = "../../testdata/testConfig.json"
	DBCONFIG   = "../../testdata/cop-db.json"
)

var serverStarted bool
var serverExitCode = 0

func createServer() *Server {
	s := new(Server)
	return s
}

func TestStartMain(t *testing.T) {
	os.Setenv("COP_HOME", homeDir)

	os.Setenv("COP_DEBUG", "true")
	// os.Setenv("COP_HOME", homeDir)
	startServer()
	time.Sleep(3 * time.Second)

	os.RemoveAll(homeDir)
}

func startServer() int {
	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		// os.Setenv("COP_HOME", homeDir)
		go runServer()
		time.Sleep(3 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
	return serverExitCode
}

func runServer() {
	os.Setenv("COP_DEBUG", "true")
	os.Setenv("COP_HOME", homeDir)
	Start("../../testdata")
}

func TestRegisterUser(t *testing.T) {
	copServer := `{"serverAddr":"http://localhost:8888"}`
	c, _ := factory.NewClient(copServer)

	req := &idp.RegistrationRequest{
		Name: "TestUser1",
		Type: "Client",
	}

	id, _ := factory.NewIdentity()
	identity, err := ioutil.ReadFile("../../testdata/client.json")
	if err != nil {
		t.Error(err)
	}
	util.Unmarshal(identity, id, "identity")

	req.Registrar = id

	c.Register(req)
}

func TestEnrollUser(t *testing.T) {
	copServer := `{"serverAddr":"http://localhost:8888"}`
	c, _ := factory.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	c.Enroll(req)
}

func testCreateHome(s *Server, t *testing.T) {
	t.Log("Test Creating Home Directory")
	os.Setenv("HOME", "/tmp/Home")

	_, err := s.CreateHome()
	if err != nil {
		t.Errorf("Failed to create home directory, error: %s", err)
	}

	if _, err := os.Stat(homeDir); err != nil {
		if os.IsNotExist(err) {
			t.Error("Failed to create home directory")
		}
	}

	os.RemoveAll("/tmp/Home")
}

func testConfigureAndBootstrapDB(s *Server, t *testing.T) {
	t.Log("Test creating database and tables during server startup")
	cfg := new(Config)
	cfg.DBdriver = "sqlite3"
	cfg.ConfigFile = configFile

	err := s.ConfigureDB(dataSource, cfg)
	if err != nil {
		t.Errorf("Failed to create database, error: %s", err)
	}

}
