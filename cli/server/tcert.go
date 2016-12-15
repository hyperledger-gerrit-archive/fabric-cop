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
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	cerr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-cop/lib/tcert"
	"github.com/hyperledger/fabric-cop/util"
)

// Handler for tcert requests
type tcertHandler struct {
	mgr     *tcert.Mgr
	keyTree *tcert.KeyTree
}

// NewTCertHandler is constructor for tcert handler
func NewTCertHandler() (h http.Handler, err error) {
	mgr, err := tcert.LoadMgr(CFG.CAKey, CFG.CACert)
	if err != nil {
		return nil, err
	}
	// TODO: The root prekey must be stored persistently in DB and retrieved here if not found
	rootKey := tcert.CreateRootPreKey()
	keyTree := tcert.NewKeyTree(rootKey)
	return &api.HTTPHandler{
		Handler: &tcertHandler{mgr: mgr, keyTree: keyTree},
		Methods: []string{"POST"},
	}, nil
}

// Handle a tcert request
func (h *tcertHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	err := h.handle(w, r)
	if err != nil {
		return cerr.NewBadRequest(err)
	}
	return nil
}

func (h *tcertHandler) handle(w http.ResponseWriter, r *http.Request) error {

	// Read and unmarshall the request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("Failure reading request body: %s", err)
	}
	tcertReq := &tcert.GetBatchRequest{}
	err = util.Unmarshal(body, tcertReq, "tcert request")
	if err != nil {
		return err
	}

	// Get an X509 certificate from the authorization header associated with the caller
	cert, err := getCertFromAuthHdr(r)
	if err != nil {
		return err
	}

	// Get the user's affiliation group's prekey and attribute values and fill in
	// the request with this information
	id := tcert.GetEnrollmentIDFromCert(cert)
	attrs, affiliationPath, err := getUserInfo(id, tcertReq.AttrNames)
	if err != nil {
		return err
	}
	tcertReq.PreKey = h.keyTree.GetKey(affiliationPath)
	tcertReq.Attrs = attrs

	// Call the tcert library to get the batch of tcerts
	resp, err := h.mgr.GetBatch(tcertReq, cert)
	if err != nil {
		return err
	}

	// Write the response
	api.SendResponse(w, resp)

	// Success
	return nil

}

// Get the X509 certificate from the authorization header of the request
func getCertFromAuthHdr(r *http.Request) (*x509.Certificate, error) {
	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		return nil, errNoAuthHdr
	}
	cert, _, _, err := util.DecodeToken(authHdr)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// getUserinfo returns the users requested attribute values and user's affiliation path
func getUserInfo(id string, attrNames []string) ([]tcert.Attribute, []string, error) {
	registry := CFG.UserRegistry
	user, err := registry.GetUser(id, attrNames)
	if err != nil {
		return nil, nil, err
	}
	if err != nil {
		log.Fatal("Failed to get RootPreKey")
		return nil, nil, err
	}
	attrs := make([]tcert.Attribute, 0)
	for _, name := range attrNames {
		value := user.GetAttribute(name)
		if value != "" {
			attrs = append(attrs, tcert.Attribute{Name: name, Value: value})
		}
	}
	return attrs, user.GetAffiliationPath(), nil
}
