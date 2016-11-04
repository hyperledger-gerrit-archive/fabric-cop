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
	"errors"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"io/ioutil"
)

var initUsageText = `cop server init CSRJSON -- generates a new private key and self-signed certificate
Usage:
        cop server init CSRJSON
Arguments:
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin
Flags:
`

var initFlags = []string{"initca", "config"}

// initMain creates the private key and self-signed certificate needed to start COP Server
func initMain(args []string, c cli.Config) (err error) {
	s := new(Server)
	COP_HOME, err := s.CreateHome()
	if err != nil {
		return err
	}
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

	if c.IsCA {
		var key, csrPEM, cert []byte
		cert, csrPEM, key, err = initca.New(&req)
		if err != nil {
			return
		}

		certerr := ioutil.WriteFile(COP_HOME+"/server-cert.pem", cert, 0755)
		if certerr != nil {
			log.Fatal("Error writing server-cert.pem to $COP_HOME directory")
		}
		keyerr := ioutil.WriteFile(COP_HOME+"/server-key.pem", key, 0755)
		if keyerr != nil {
			log.Fatal("Error writing server-key.pem to $COP_HOME directory")
		}

		cli.PrintCert(key, csrPEM, cert)
	} else {
		if req.CA != nil {
			err = errors.New("ca section only permitted in initca")
			return
		}

		var key, csrPEM []byte
		g := &csr.Generator{Validator: Validator}
		csrPEM, key, err = g.ProcessRequest(&req)
		if err != nil {
			key = nil
			return
		}

		cli.PrintCert(key, csrPEM, nil)
	}
	return nil
}

// Validator does nothing and will never return an error. It exists because creating a
// csr.Generator requires a Validator.
func Validator(req *csr.CertificateRequest) error {
	return nil
}

// Command assembles the definition of Command 'genkey -initca'
var InitCommand = &cli.Command{UsageText: initUsageText, Flags: initFlags, Main: initMain}
