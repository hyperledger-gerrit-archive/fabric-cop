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
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
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

// Handle a reenroll request
// It is the same as an enroll request except that the authorization header
// was different, as handled in auth.go
func (h *reenrollHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("reenroll request received")
	return handleEnrollRequest(w, r)
}
