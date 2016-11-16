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
	"path/filepath"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
)

// reenrollHandler for register requests
type reenrollHandler struct {
}

// NewReenrollHandler is constructor for register handler
func NewReenrollHandler() (h http.Handler, err error) {
	// NewHandler is constructor for register handler
	return &api.HTTPHandler{
		Handler: &reenrollHandler{},
		Methods: []string{"POST"},
	}, nil
}

// Handle a enroll request
func (h *reenrollHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("reenroll request received")

	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		log.Debug("no authorization header")
		return errNoAuthHdr
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	user, err := util.VerifyToken(authHdr, body)
	if err != nil {
		return err
	}

	reenroll := NewReenrollUser()
	cert, err := reenroll.Enroll(user, body)
	if err != nil {
		return err
	}

	return api.SendResponse(w, cert)
}

// Reenroll is for enrolling a user
type Reenroll struct {
	DB         *sqlx.DB
	DbAccessor *Accessor
	cfg        *Config
}

// NewReenrollUser is a constructor
func NewReenrollUser() *Reenroll {
	e := new(Reenroll)
	e.cfg = CFG
	home := e.cfg.Home
	dataSource := filepath.Join(home, e.cfg.DataSource)
	e.DB, _ = util.GetDB(e.cfg.DBdriver, dataSource)
	e.DbAccessor = NewDBAccessor()
	e.DbAccessor.SetDB(e.DB)
	return e
}

// Enroll will enroll a user
func (e *Reenroll) Enroll(id string, csrPEM []byte) ([]byte, cop.Error) {
	log.Debugf("Received request to reenroll user with id: %s\n", id)
	mutex.Lock()
	defer mutex.Unlock()

	_, err := e.DbAccessor.GetUser(id)
	if err != nil {
		log.Error("User not registered")
		return nil, cop.WrapError(err, cop.EnrollingUserError, "User not registered")
	}

	return e.signKey(csrPEM)
}

// func (e *Enroll) signKey(csrPEM []byte, remoteHost string) ([]byte, cop.Error) {
func (e *Reenroll) signKey(csrPEM []byte) ([]byte, cop.Error) {
	log.Debugf("signKey")
	var cfg cli.Config
	cfg.CAFile = e.cfg.CACert
	cfg.CAKeyFile = e.cfg.CAKey
	s, err := sign.SignerFromConfigAndDB(cfg, e.DB)
	if err != nil {
		log.Errorf("SignerFromConfig error: %s", err)
		return nil, cop.WrapError(err, cop.CFSSL, "failed in SignerFromConfig")
	}
	req := signer.SignRequest{
		// Hosts:   signer.SplitHosts(c.Hostname),
		Request: string(csrPEM),
		// Profile: c.Profile,
		// Label:   c.Label,
	}
	cert, err := s.Sign(req)
	if err != nil {
		log.Errorf("Sign error: %s", err)
		return nil, cop.WrapError(err, cop.CFSSL, "failed in Sign")
	}
	log.Debug("Sign success")
	return cert, nil

}
