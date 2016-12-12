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
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/util"
)

// enrollHandler for register requests
type enrollHandler struct {
}

// NewEnrollHandler is constructor for register handler
func NewEnrollHandler() (h http.Handler, err error) {
	// NewHandler is constructor for register handler
	return &api.HTTPHandler{
		Handler: &enrollHandler{},
		Methods: []string{"POST"},
	}, nil
}

// Handle a enroll request
func (h *enrollHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("enroll request received")
	return handleEnrollRequest(w, r)
}

// handleEnrollRequest does the real work and is same as for reenroll,
// except that the authorization header was different and handled by auth.go
func handleEnrollRequest(w http.ResponseWriter, r *http.Request) error {
	// Read the request's body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Unmarshall request body
	var req signer.SignRequest
	err = util.Unmarshal(body, &req, "enrollment request")
	if err != nil {
		return err
	}

	// Sign the request
	cert, err := CFG.Signer.Sign(req)
	if err != nil {
		log.Errorf("Sign error during reenroll: %s", err)
		return cop.WrapError(err, cop.CFSSL, "reenroll failed in Sign")
	}

	return api.SendResponse(w, cert)
}
