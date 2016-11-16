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
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/sign"
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

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	user, token, ok := r.BasicAuth()
	if !ok {
		log.Error("No authorization header set")
		return cop.NewError(cop.EnrollingUserError, "No authorization header set")
	}

	enroll := NewEnrollUser()
	cert, err := enroll.Enroll(user, []byte(token), body)
	if err != nil {
		return err
	}

	return api.SendResponse(w, cert)
}

// Enroll encapsulates the Config and functionality needed for user enrollment
type Enroll struct {
	cfg *Config
}

// NewEnrollUser is a constructor
func NewEnrollUser() *Enroll {
	e := new(Enroll)
	e.cfg = CFG
	return e
}

// Enroll will enroll an already registered user and provided an enrollment cert
func (e *Enroll) Enroll(id string, token []byte, csrPEM []byte) ([]byte, cop.Error) {
	log.Debugf("Received request to enroll user with id: %s\n", id)
	mutex.Lock()
	defer mutex.Unlock()

	user, err := e.cfg.DBAccessor.GetUser(id)
	if err != nil {
		log.Error("User not registered")
		return nil, cop.WrapError(err, cop.EnrollingUserError, "User not registered")
	}

	if !bytes.Equal(token, []byte(user.Token)) {
		log.Error("Identity or token does not match")
		return nil, cop.NewError(cop.EnrollingUserError, "Identity or token does not match")
	}

	if user.State == 0 {
		cert, signErr := e.signKey(csrPEM)
		if signErr != nil {
			log.Error("Failed to sign CSR")
			return nil, signErr
		}

		tok := util.RandomString(12)

		updateState := cop.UserRecord{
			ID:       user.ID,
			Token:    tok,
			Metadata: user.Metadata,
			State:    1,
		}

		err = e.cfg.DBAccessor.UpdateUser(updateState)
		if err != nil {
			return nil, cop.WrapError(err, cop.EnrollingUserError, "Failed to updates user state")
		}

		return cert, nil
	}
	return nil, cop.NewError(cop.EnrollingUserError, "User was not enrolled")
}

// signKey will sign a client cert with a host name by a given CA and CA key
func (e *Enroll) signKey(csrPEM []byte) ([]byte, cop.Error) {
	log.Debugf("signKey")
	var cfg cli.Config
	cfg.CAFile = e.cfg.CACert
	cfg.CAKeyFile = e.cfg.CAKey
	s, err := sign.SignerFromConfigAndDB(cfg, e.cfg.DB)
	if err != nil {
		log.Errorf("Failed to create signer [error: %s]", err)
		return nil, cop.WrapError(err, cop.CFSSL, "Failed to create signer")
	}
	req := signer.SignRequest{
		Request: string(csrPEM),
	}
	cert, err := s.Sign(req)
	if err != nil {
		log.Errorf("Failed to sign certificate [error: %s]", err)
		return nil, cop.WrapError(err, cop.CFSSL, "Failed to sign certificate")
	}
	log.Debug("Sign success")
	return cert, nil

}
