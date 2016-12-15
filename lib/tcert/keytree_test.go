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
)

func TestKeyTree(t *testing.T) {

	log.Level = log.LevelDebug

	rootKey := CreateRootPreKey()
	path := []string{"A", "B", "C"}

	tree1 := NewKeyTree(rootKey)
	tree2 := NewKeyTree(rootKey)
	key1 := tree1.GetKey(path)
	key2 := tree2.GetKey(path)

	if key1 != key2 {
		t.Errorf("key gen failure: %s != %s", key1, key2)
	}

}
