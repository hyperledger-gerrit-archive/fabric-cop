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
	"encoding/json"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/serve"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"io/ioutil"
	"os"
	"path/filepath"
)

var initUsageText = `cop server init CSRJSON -- generates a new private key and self-signed certificate
Usage:
        cop server init CSRJSON
Arguments:
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin
Flags:
`

var initFlags = []string{"initca", "config"}

// InitCommand calls the command to geneates a private key and self-signed certificate
func InitCommand() {
	cmds := map[string]*cli.Command{
		"init": InitServerCommand,
	}
	// Set the authentication handler
	serve.SetWrapHandler(NewAuthWrapper)
	// Add the "register" route/endpoint
	//	serve.SetEndpoint("register", NewRegisterHandler)
	// Add the "enroll" route/endpoint
	//	serve.SetEndpoint("enroll", NewEnrollHandler)

	// If the CLI returns an error, exit with an appropriate status code.
	err := cli.Start(cmds)
	if err != nil {
		os.Exit(1)
	}
}

// initMain creates the private key and self-signed certificate needed to start COP Server
func initMain(args []string, c cli.Config) (err error) {
	csrFile, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return
	}

	csrFileBytes, err := cli.ReadStdin(csrFile)
	if err != nil {
		return
	}

	req := csr.CertificateRequest{
		KeyRequest: csr.NewBasicKeyRequest(),
	}
	err = json.Unmarshal(csrFileBytes, &req)
	if err != nil {
		return
	}

	c = cli.Config{
		IsCA: true,
	}

	var key, cert []byte
	cert, _, key, err = initca.New(&req)
	if err != nil {
		return
	}

	s := new(Server)
	COPHome, err := s.CreateHome()
	if err != nil {
		return
	}
	certerr := ioutil.WriteFile(COPHome+"/server-cert.pem", cert, 0755)
	if certerr != nil {
		log.Fatal("Error writing server-cert.pem to $COPHome directory")
	}
	keyerr := ioutil.WriteFile(COPHome+"/server-key.pem", key, 0755)
	if keyerr != nil {
		log.Fatal("Error writing server-key.pem to $COPHome directory")
	}

	return nil
}

// Init takes a CSRJSON file and outputs private key and self-signed cert
func Init(dir string) {
	osArgs := os.Args
	CSRJSON := filepath.Join(dir, "csr_ecdsa.json")
	//key := filepath.Join(dir, "ec-key.pem")
	//config := filepath.Join(dir, "enrollConfig.json")
	//dbconfig := filepath.Join(dir, "cop-db.json")
	os.Args = []string{"server", "init", CSRJSON}
	InitCommand()
	os.Args = osArgs
}

// InitServerCommand assembles the definition of Command 'genkey -initca CSRJSON'
var InitServerCommand = &cli.Command{UsageText: initUsageText, Flags: initFlags, Main: initMain}
