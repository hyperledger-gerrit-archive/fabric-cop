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

package tcert

import (
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/core/crypto/bccsp"
	"github.com/hyperledger/fabric/core/crypto/bccsp/factory"
)

func TestKeyTree(t *testing.T) {

	log.Level = log.LevelDebug

	path := []string{"A", "B", "C"}

	csp, err := factory.GetDefault()
	if err != nil {
		t.Fatalf("Failed to get BCCSP factory: %s", err)
	}
	opts := &bccsp.AES256KeyGenOpts{Temporary: true}
	rootKey, err := csp.KeyGen(opts)
	if err != nil {
		t.Fatalf("Failed to create root key: %s", err)
	}

	tree1 := NewKeyTree(csp, rootKey)
	key1, err := tree1.GetKey(path)
	if err != nil {
		t.Fatalf("Failed to get key1: %s", err)
	}

	tree2 := NewKeyTree(csp, rootKey)
	key2, err := tree2.GetKey(path)
	if err != nil {
		t.Fatalf("Failed to get key2: %s", err)
	}

	ski1 := key1.SKI()
	ski2 := key2.SKI()
	if !bytesEqual(ski1, ski2) {
		t.Errorf("keys are not equal %s != %s", ski1, ski2)
	}

}

func bytesEqual(a, b []byte) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}