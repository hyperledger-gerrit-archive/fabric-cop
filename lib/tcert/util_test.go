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
	"io/ioutil"
	"math/big"
	"testing"

	"crypto/rand"
	"encoding/base64"
)

func TestGenNumber(t *testing.T) {
	var numlen int64
	numlen = 20
	GenNumber(big.NewInt(numlen))
}

func TestECCertificate(t *testing.T) {
	publicKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("Cannot read EC Certificate from file system")
	}
	_, error := GetCertificate(publicKeyBuff)
	if error != nil {
		t.Fatalf("Cannot create EC Certificate \t [%v]", error)
	}
}

func TestCBCPKCS7EncryptCBCPKCS7Decrypt(t *testing.T) {

	// Note: The purpose of this test is not to test AES-256 in CBC mode's strength
	// ... but rather to verify the code wrapping/unwrapping the cipher.
	key := make([]byte, AESKeyLength)
	rand.Reader.Read(key)

	//                  123456789012345678901234567890123456789012
	var ptext = []byte("a message with arbitrary length (42 bytes)")

	encrypted, encErr := CBCPKCS7Encrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, encErr)
	}

	decrypted, dErr := CBCPKCS7Decrypt(key, encrypted)
	if dErr != nil {
		t.Fatalf("Error decrypting the encrypted '%s': %v", ptext, dErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Decrypt( Encrypt( ptext ) ) != ptext: Ciphertext decryption with the same key must result in the original plaintext!")
	}

}

func TestPreKey(t *testing.T) {
	rootKey := CreateRootPreKey()
	if len(rootKey) == 0 {
		t.Fatal("Root Key Cannot be generated")
	}

}

func TestSerialNumber(t *testing.T) {
	publicKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("Cannot read EC Certificate from file system")
	}
	_, error := GetCertitificateSerialNumber(publicKeyBuff)

	if error != nil {
		t.Fatalf("Cannot create EC Certificate \t [%v]", error)
	}

}

func TestGetBadCertificate(t *testing.T) {
	certBuff, err := ioutil.ReadFile("../../testdata/badcertdatatest.pptx")
	if err != nil {
		t.Fatalf("Cannot read certificate from file system")
	}

	encoded := base64.StdEncoding.EncodeToString(certBuff)
	cert, derror := base64.StdEncoding.DecodeString(encoded)

	if derror != nil {
		t.Fatalf("decoding certificate error:\t [%v] ", derror)
	}

	_, certerr := GetCertificate([]byte(cert))
	if certerr == nil {
		t.Fatalf("Should have failed since certBuff is in der:\t [%v] ", certerr)
	}
}

func TestGenerateUUID(t *testing.T) {
	intuuid := GenerateIntUUID()
	if intuuid == nil {
		t.Error("UUID is not generated")
	}
}

func TestDerToPem(t *testing.T) {

	derCertBuff, certErr := ioutil.ReadFile("../../testdata/testCert.der")
	if certErr != nil {
		t.Fatalf("Cannot read Certificate in DER format")
	}
	pemCert := ConvertDERToPEM(derCertBuff, "CERTIFICATE")

	fileError := ioutil.WriteFile("../../testdata/pemCert.pem", pemCert, 0777)
	if fileError != nil {
		t.Fatalf("Problem in writing TCert Response file")
	}

}
