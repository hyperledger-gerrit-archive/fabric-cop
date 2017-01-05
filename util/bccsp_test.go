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

package util

import (
	"io/ioutil"
	"testing"
)

func TestBCCSP(t *testing.T) {
	dir, err := ioutil.TempDir("", "home")
	if err != nil {
		t.Fatalf("Failed to create temp directory [error: %s]", err)
	}

	csp, err := InitBCCSP(dir)
	if err != nil {
		t.Fatalf("GetBCCSP failed: %s", err)
	}
	_, err = GenRootKey(csp)
	if err != nil {
		t.Fatalf("GenRootKey failed: %s", err)
	}
}

func TestBCCSPSignerFromSKI(t *testing.T) {
	dir := "../testdata"

	csp, err := InitBCCSP(dir)
	if err != nil {
		t.Fatalf("GetBCCSP failed: %s", err)
	}

	_, err = GetSignerFromSKIFile("../testdata/ec-key.ski", csp)
	if err != nil {
		t.Fatalf("Failed to load %s: %s", "../testdata/ec-key.ski", err)
	}

	_, err = GetSignerFromSKIFile("../testdata/ec-key.pem", csp)
	if err == nil {
		t.Fatalf("Expected failure, bad file")
	}

	_, err = GetSignerFromSKIFile("", csp)
	if err == nil {
		t.Fatalf("Expected failure, no file")
	}

	_, err = GetSignerFromSKIFile("../testdata/ec-key.ski", nil)
	if err == nil {
		t.Fatalf("Expected failure, no csp")
	}
}
