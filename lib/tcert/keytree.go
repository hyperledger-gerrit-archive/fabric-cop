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

import "strings"

/*
 * A key tree is a hierarchy of derived keys with a single root key.
 * This structure is useful to enable releasing information to an auditor
 * in a limited way.  In particular, by releasing a key anywhere in the
 * tree of keys, an auditor can verify or view all information associated
 * with information using the key at this node or any child nodes.
 * All keys in the tree can be derived from the root key + the path.
 */

const (
	keyPathSep = "/"
)

// NewKeyTree is the constructor for a key tree
func NewKeyTree(rootKey string) *KeyTree {
	return &KeyTree{
		rootKey: rootKey,
		keys:    make(map[string]string),
	}
}

// KeyTree is a tree of derived keys
type KeyTree struct {
	rootKey string
	keys    map[string]string
}

// GetKey returns the value of a derived key for the specified path
func (m *KeyTree) GetKey(path []string) string {
	if len(path) == 0 {
		return m.rootKey
	}
	name := strings.Join(path, keyPathSep)
	key := m.keys[name]
	if key != "" {
		return key
	}
	parentKey := m.GetKey(path[0 : len(path)-1])
	// TODO: Use BCCSP's DeriveKey interface to derive the child tree from parent
	key = parentKey
	m.keys[name] = key
	return key
}
