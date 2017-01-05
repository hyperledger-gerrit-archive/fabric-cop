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
	"crypto"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/hyperledger/fabric/core/crypto/bccsp"
	"github.com/hyperledger/fabric/core/crypto/bccsp/factory"
	"github.com/hyperledger/fabric/core/crypto/bccsp/signer"
	"github.com/hyperledger/fabric/core/crypto/bccsp/sw"
)

// InitBCCSP creates bccsp with keystore under home directory
func InitBCCSP(home string) (bccsp.BCCSP, error) {
	// For now hardcode to use SW BCCSP
	ks := &sw.FileBasedKeyStore{}
	err := ks.Init(nil, home+"/ks", false)
	if err != nil {
		panic(fmt.Errorf("Failed initializing key store [%s]", err))
	}

	// For now hardcode the SW BCCSP. This should be made parametrizable via json cfg once there are more BCCSPs
	bccspOpts := &factory.SwOpts{Ephemeral_: true, SecLevel: 256, HashFamily: "SHA2", KeyStore: ks}
	return factory.GetBCCSP(bccspOpts)
}

// GenRootKey generates a new root key
func GenRootKey(csp bccsp.BCCSP) (bccsp.Key, error) {
	opts := &bccsp.AES256KeyGenOpts{Temporary: true}
	return csp.KeyGen(opts)
}

// PemType PEM header for BCCSP SKI files
var PemType = "BCCSP SKI"

// GetSignerFromSKI load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromSKI(ski []byte, csp bccsp.BCCSP) (crypto.Signer, error) {
	if csp == nil {
		return nil, fmt.Errorf("CFG.csp was not initialized")
	}

	privateKey, err := csp.GetKey(ski)
	if err != nil {
		return nil, fmt.Errorf("Failed to load ski from bccsp %s", err.Error())
	}

	signer := &signer.CryptoSigner{}
	if err = signer.Init(csp, privateKey); err != nil {
		return nil, fmt.Errorf("Failed to load ski from bccsp %s", err.Error())
	}
	return signer, nil
}

// GetSignerFromSKIFile load skiFile and load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromSKIFile(skiFile string, csp bccsp.BCCSP) (crypto.Signer, error) {
	keyBuff, err := ioutil.ReadFile(skiFile)
	if err != nil {
		return nil, fmt.Errorf("Could not read skiFile [%s]: %s", skiFile, err.Error())
	}

	block, _ := pem.Decode(keyBuff)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding file [%s]", skiFile)
	}

	if block.Type != PemType {
		return nil, fmt.Errorf("Decoded PEM type does not match expected: [%s] got: [%s]", PemType, block.Type)
	}

	return GetSignerFromSKI(block.Bytes, csp)
}
