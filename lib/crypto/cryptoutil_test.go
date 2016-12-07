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

package crypto

import (
	"io/ioutil"
	"math/big"
	"testing"

	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"

	"github.com/cloudflare/cfssl/log"
	"github.com/stretchr/stew/objects"
)

func TestRSASignAndVerify(t *testing.T) {
	privKeyBuff, err := ioutil.ReadFile("../../testdata/rsaPrivateKey.pem")
	if err != nil {
		t.Fatalf("Unable to read private key PEM from file: [%v]", err)
	}
	rsaPrivateKey, err := GetPrivateKey(privKeyBuff)
	if err != nil {
		t.Fatalf("Unable to get private key: [%v]", err)
	}

	certBuff, certErr := ioutil.ReadFile("../../testdata/rsaCertificate.pem")
	if certErr != nil {
		t.Fatalf("Error reading certificate PEM file: %v", certErr)
	}

	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")
	signatureJSON := ConvertJSONFileToJSONString("../../testdata/signature.json")

	cert := base64.StdEncoding.EncodeToString(certBuff)
	signedJSON, signError := RSASignJSON(jsonString, "SHA2_384", signatureJSON, rsaPrivateKey.(*rsa.PrivateKey), cert)
	if signError != nil {
		t.Fatalf("json sign error : [%v]", signError)
	}
	rsaverified := VerifyMessage(jsonString, signedJSON)
	if rsaverified == false {
		t.Fatalf("Verification failed in TestRSASignAndVerify")
	}
}

func TestECSignAndVerify(t *testing.T) {

	privateKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest-key.pem")
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot read EC Private Key File")
	}
	privateKey, err := GetPrivateKey(privateKeyBuff)
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot Generate EC Private Key Object")
	}

	CertificateBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot read EC Certificate File")
	}
	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")
	signatureJSON := ConvertJSONFileToJSONString("../../testdata/signature.json")
	signedJSON := SignECMessage(jsonString, signatureJSON, privateKey, CertificateBuff)

	ECverified := VerifyMessage(jsonString, signedJSON)
	if ECverified == false {
		t.Fatalf("Verification failed ")
	}
}

func TestRSAPubKeyAltered(t *testing.T) {
	privKeyBuff, err := ioutil.ReadFile("../../testdata/rsaPrivateKey.pem")
	if err != nil {
		t.Fatalf("Unable to read RSA private key PEM from file")
	}
	rsaPrivateKey, err := GetPrivateKey(privKeyBuff)
	if err != nil {
		log.Fatalf("Cannot get PrivateKey")
	}

	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")
	signatureJSON := ConvertJSONFileToJSONString("../../testdata/signature.json")

	certBuff, certErr := ioutil.ReadFile("../../testdata/rsaCertificate.pem")
	if certErr != nil {
		t.Fatalf("Error reading certificate PEM file:\t [%v]", certErr)
	}

	cert := base64.StdEncoding.EncodeToString(certBuff) + "RSA"

	signedSON, rsaSignError := RSASignJSON(jsonString, "SHA2_384", signatureJSON, rsaPrivateKey.(*rsa.PrivateKey), cert)

	if rsaSignError != nil {
		t.Fatalf("TestRSAPubKeyAltered : RSA Sign failed\t [%v]", rsaSignError)
	}
	isrsaverified := VerifyMessage(jsonString, signedSON)

	if isrsaverified == true {
		t.Fatalf("Verification should have failed due to RSA public key altered.")
	}

}

func TestECMessageAltered(t *testing.T) {

	privateKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest-key.pem")
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot read EC Private Key File")
	}
	privateKey, err := GetPrivateKey(privateKeyBuff)
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot Generate EC Private Key Object")
	}

	CertificateBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot read EC Certificate File")
	}

	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")
	signatureJSON := ConvertJSONFileToJSONString("../../testdata/signature.json")
	signedJSON := SignECMessage(jsonString, signatureJSON, privateKey, CertificateBuff)

	jsonMap, _ := objects.NewMapFromJSON(signedJSON)
	key := "ECSignature.R"
	_ = jsonMap.Set(key, "newRvalue")
	newsignedJSON, _ := jsonMap.JSON()

	isECverified := VerifyMessage(jsonString, newsignedJSON)
	if isECverified != false {
		t.Fatalf("Verification failed due to altered message")
	}
}

func TestCertExpiry(t *testing.T) {

	privateKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest-key.pem")
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot read EC Private Key File")
	}
	privateKey, err := GetPrivateKey(privateKeyBuff)
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot Generate EC Private Key Object")
	}

	CertificateBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("TestECSignAndVerify : Cannot read EC Certificate File")
	}
	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")
	signatureJSON := ConvertJSONFileToJSONString("../../testdata/signature.json")
	isVerfied := VerifyMessage(jsonString, SignECMessage(jsonString, signatureJSON, privateKey, CertificateBuff))
	if isVerfied == false {
		t.Fatalf("Verification failed due to certificate expired")
	}
}

func TestGenNumber(t *testing.T) {
	var numlen int64
	numlen = 20
	GenNumber(big.NewInt(numlen))
}

func TestPrivateKey(t *testing.T) {

	//var err error
	//Test EC Private Key in PEM format
	privateKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest-key.pem")
	if err != nil {
		t.Fatalf("Cannot read EC Private Key from file system")
	}
	_, error := GetPrivateKey(privateKeyBuff)
	if error != nil {
		t.Fatalf("Cannot create Private Key\t [%v]", error)
	}

	//Test RSA Private Key in PEM format
	rsaPemPrivateKeyBuff, error := ioutil.ReadFile("../../testdata/rsaPrivateKey.pem")
	if error != nil {
		t.Fatalf("Cannot read RSA Private Key from file system")
	}
	privKey, error := GetPrivateKey(rsaPemPrivateKeyBuff)
	if error != nil {
		t.Fatalf("Cannot create PEM RSA Private Key\t [%v]", error)
	}
	if privKey == nil {
		t.Fatalf("Cannot create PEM RSA Private Key")
	}

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
	_, error := GetCertificateSerialNumber(publicKeyBuff)

	if error != nil {
		t.Fatalf("Cannot create EC Certificate \t [%v]", error)
	}

}

func TestJsonEncryptDecrypt(t *testing.T) {

	key := make([]byte, AESKeyLength)
	rand.Reader.Read(key)

	var ptext = []byte("a message with arbitrary length (42 bytes)")
	encrypted, encErr := CBCPKCS7Encrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, encErr)
	}

	//Create Json Format
	var testDecrypt TestDecrypt
	testDecrypt.ID = "123"
	testDecrypt.EncryptedByte = encrypted

	//tcertResponse := TCertCreateSetResp{&CertSet{"123", kdfKey, set}}
	tcertResponseJSONByte, err := json.Marshal(testDecrypt)
	if err != nil {
		//log.Error(err)
		t.Fatalf("JSON Marshal issue")
	}
	encryptJSON := string(tcertResponseJSONByte)

	//Perform JOSN unmarshall
	error := json.Unmarshal([]byte(encryptJSON), &testDecrypt)
	if error != nil {
		t.Fatalf("Error JSON unmarshalling")
	}
	encrypyedMessage := testDecrypt.EncryptedByte

	decryptedMessage, decryptError := CBCPKCS7Decrypt(key, encrypyedMessage)
	if decryptError != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, decryptError)
	}
	if string(ptext) != string(decryptedMessage) {
		t.Fatalf("Decryption failed")
	} else {

	}
}

// func TestparsePrivateKey(t *testing.T) {
// 	pkcs8privKeyBuff, pkerr := ioutil.ReadFile("../../testdata/pkcs8privKey.pem")
// 	if pkerr != nil {
// 		t.Fatalf("Cannot read PKCS8 Private Key from file system")
// 	}
// 	_, pkcs8err := parsePrivateKey(pkcs8privKeyBuff)
// 	if pkcs8err != nil {
// 		t.Fatalf("Cannot parse PKCS8 Private Key from PEM, error: %s", pkcs8err)
// 	}
// }

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

func TestGetCertAKI(t *testing.T) {
	publicKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("Cannot read EC Certificate from file system")
	}
	_, error := GetCertificateAKI(publicKeyBuff)

	if error != nil {
		t.Fatalf("Failed to get certificate AKI \t [%v]", error)
	}
}
