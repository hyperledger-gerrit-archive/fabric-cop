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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	cl "github.com/hyperledger/fabric-cop/cli/client"
	"github.com/hyperledger/fabric-cop/idp"
)

var remoteinitUsageText = `cop server remoteinit -- generates a new private key and certificate signed by intermediate COP server
Usage of remoteinit:
		cop server remoteinit COP-SERVER-ADDR CSRJSON ID SECRET
Arguments:
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin
Flags:
`

var remoteinitFlags = []string{}

func remoteinitMain(args []string, c cli.Config) error {
	copServer, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}
	csrJSONFile, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	id, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}
	secret, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}
	enrollreq := &idp.EnrollmentRequest{
		Name:   id,
		Secret: secret,
	}

	client, err := cl.NewClient(copServer)
	if err != nil {
		return err
	}
	enrollreq.CSR, _ = client.LoadCSRInfo(csrJSONFile)

	// Read the CSR JSON file if provided

	ID, err := client.Enroll(enrollreq)
	if err != nil {
		return err
	}

	idbyte, _ := ID.Serialize()
	var publicSignerMap map[string]interface{}
	json.Unmarshal(idbyte, &publicSignerMap)
	tmp := publicSignerMap["publicSigner"]
	cert := tmp.(map[string]interface{})["cert"]
	decodedcert, certerr := base64.StdEncoding.DecodeString(cert.(string))
	if certerr != nil {
		log.Fatal("Error writing server-key.pem to $COPHome directory")
	}
	key := tmp.(map[string]interface{})["key"]
	decodedkey, keyerr := base64.StdEncoding.DecodeString(key.(string))
	if keyerr != nil {
		log.Fatal("Error writing server-key.pem to $COPHome directory")
	}
	s := new(Server)
	COPHome, err := s.CreateHome()
	if err != nil {
		return errors.New(err.Error())
	}
	writecerterr := ioutil.WriteFile(COPHome+"/server-cert.pem", decodedcert, 0755)
	if writecerterr != nil {
		log.Fatal("Error writing server-cert.pem to $COPHome directory")
	}
	writekeyerr := ioutil.WriteFile(COPHome+"/server-key.pem", decodedkey, 0755)
	if writekeyerr != nil {
		log.Fatal("Error writing server-key.pem to $COPHome directory")
	}

	return nil
}

// RemoteInit assembles the definition of Command 'gencert'
var RemoteInit = &cli.Command{UsageText: remoteinitUsageText, Flags: remoteinitFlags, Main: remoteinitMain}
