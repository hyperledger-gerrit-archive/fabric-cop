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
	"strings"

	"github.com/hyperledger/fabric/core/crypto/bccsp"
)

/*
 * A key tree is a hierarchy of derived keys with a single root key.
 * This structure is useful to release information to an auditor
 * in a limited way.  In particular, each node in the tree has a key
 * and a name.  The key should be kept secret and the name need not be
 * secret.
 * child ( key anywhere in the
 * tree of keys, an auditor can verify or view all information associated
 * with information using the key at this node or any child nodes.
 * All keys in the tree can be derived from the root key + the path.
 */

const (
	keyPathSep = "/"
)

// NewKeyTree is the constructor for a key tree
func NewKeyTree(bccspMgr bccsp.BCCSP, rootKey bccsp.Key) *KeyTree {
	tree := new(KeyTree)
	tree.bccspMgr = bccspMgr
	tree.rootKey = rootKey
	tree.keys = make(map[string]bccsp.Key)
	return tree
}

// KeyTree is a tree of derived keys
type KeyTree struct {
	bccspMgr bccsp.BCCSP
	rootKey  bccsp.Key
	keys     map[string]bccsp.Key
}

// GetKey returns the value of a derived key for the specified path
func (m *KeyTree) GetKey(path []string) (bccsp.Key, error) {
	if len(path) == 0 {
		return m.rootKey, nil
	}
	name := strings.Join(path, keyPathSep)
	key := m.keys[name]
	if key != nil {
		return key, nil
	}
	parentKey, err := m.GetKey(path[0 : len(path)-1])
	if err != nil {
		return nil, err
	}
	childName := path[len(path)-1]
	key, err = m.deriveKey(parentKey, childName)
	if err != nil {
		return nil, err
	}
	m.keys[name] = key
	return key, nil
}

// Given a parentKey and a childName, return the child's derived key
func (m *KeyTree) deriveKey(parentKey bccsp.Key, childName string) (bccsp.Key, error) {
	opts := &bccsp.HMACDeriveKeyOpts{
		Temporary: true,
		Arg:       []byte(childName),
	}
	return m.bccspMgr.KeyDeriv(parentKey, opts)
}
