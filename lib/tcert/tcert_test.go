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
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"testing"

	crypto "github.com/hyperledger/fabric-cop/lib/crypto"
)

func TestTCertWithoutAttribute(t *testing.T) {

	privateKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest-key.pem")
	if err != nil {
		t.Fatalf("TestTCertWithoutAttribute : Cannot read EC Private Key File")
	}
	privateKey, err := crypto.GetPrivateKey(privateKeyBuff)
	if err != nil {
		t.Fatalf("TestTCertWithoutAttribute : Cannot Generate EC Private Key Object")
	}

	CertificateBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("TestTCertWithoutAttribute : Cannot read EC Certificate File")
	}

	jsonString := crypto.ConvertJSONFileToJSONString("../../testdata/tcertrequestwithoutattr.json")
	signatureJSON := crypto.ConvertJSONFileToJSONString("../../testdata/signature.json")
	signedJSON := crypto.SignECMessage(jsonString, signatureJSON, privateKey, CertificateBuff)

	tcertResponse, error := GetCertificateSet(jsonString, signedJSON)
	if (error != nil) || (len(tcertResponse) == 0) {
		t.Fatalf("Problem in creating TCert Response")
	}
	//Need to delete file later on when testing is complete
	fileError := ioutil.WriteFile("../../testdata/tcertresponse.json", []byte(tcertResponse), 0777)
	if fileError != nil {
		t.Fatalf("Problem in writing TCert Response file")
	}

}

func TestTcertWithMalformedRequestJSon(t *testing.T) {

	privateKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest-key.pem")
	if err != nil {
		t.Fatalf("TestTcertWithMalformedRequestJSon : Cannot read EC Private Key File")
	}
	privateKey, err := crypto.GetPrivateKey(privateKeyBuff)
	if err != nil {
		t.Fatalf("TestTcertWithMalformedRequestJSon : Cannot Generate EC Private Key Object")
	}

	CertificateBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("TestTcertWithMalformedRequestJSon : Cannot read EC Certificate File")
	}

	jsonString := crypto.ConvertJSONFileToJSONString("../../testdata/tcertmalformedrequest.json")
	signatureJSON := crypto.ConvertJSONFileToJSONString("../../testdata/signature.json")
	signedJSON := crypto.SignECMessage(jsonString, signatureJSON, privateKey, CertificateBuff)

	_, marshalerror := GetCertificateSet(jsonString, signedJSON)
	if marshalerror != nil {
		t.Logf("Error returned = [%v]", marshalerror)
	}

}

//TestTCertWithWellFormedAttributes tests TCert Creation with Attributes
func TestTCertWithWellFormedUnencryptedAttributes(t *testing.T) {

	privateKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest-key.pem")
	if err != nil {
		t.Fatalf("TestTCertWithWellFormedAttributes : Cannot read EC Private Key File")
	}
	privateKey, err := crypto.GetPrivateKey(privateKeyBuff)
	if err != nil {
		t.Fatalf("TestTCertWithWellFormedAttributes : Cannot Generate EC Private Key Object")
	}

	CertificateBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("TestTCertWithWellFormedAttributes : Cannot read EC Certificate File")
	}

	jsonString := crypto.ConvertJSONFileToJSONString("../../testdata/tcertrequestwithunencryptedattributes.json")
	signatureJSON := crypto.ConvertJSONFileToJSONString("../../testdata/signature.json")
	signedJSON := crypto.SignECMessage(jsonString, signatureJSON, privateKey, CertificateBuff)

	tcertResponse, error := GetCertificateSet(jsonString, signedJSON)
	if len(tcertResponse) == 0 {
		t.Fatalf("tcert response is nil")
	}
	if error != nil {
		t.Fatalf("Problem in creating TCert Response")
	}

	//Need to delete file later on when testing is complete
	fileError := ioutil.WriteFile("../../testdata/tcertResponse2.json", []byte(tcertResponse), 0777)
	if fileError != nil {
		t.Fatalf("Problem in writing TCert Response file")
	}
}
func TestTCertWithMalformedAttributes(t *testing.T) {

}

func TestTCertWithEncryptionEnabled(t *testing.T) {

	privateKeyBuff, err := ioutil.ReadFile("../../testdata/ecTest-key.pem")
	if err != nil {
		t.Fatalf("TestTCertWithWellFormedAttributes : Cannot read EC Private Key File")
	}
	privateKey, err := crypto.GetPrivateKey(privateKeyBuff)
	if err != nil {
		t.Fatalf("TestTCertWithWellFormedAttributes : Cannot Generate EC Private Key Object")
	}

	CertificateBuff, err := ioutil.ReadFile("../../testdata/ecTest.pem")
	if err != nil {
		t.Fatalf("TestTCertWithWellFormedAttributes : Cannot read EC Certificate File")
	}

	jsonString := crypto.ConvertJSONFileToJSONString("../../testdata/tcertrequestwithencryptedattributes.json")
	signatureJSON := crypto.ConvertJSONFileToJSONString("../../testdata/signature.json")
	signedJSON := crypto.SignECMessage(jsonString, signatureJSON, privateKey, CertificateBuff)

	tcertResponse, error := GetCertificateSet(jsonString, signedJSON)
	if error != nil {
		t.Fatalf("Problem in creating TCert Response")
	}
	//Need to delete file later on when testing is complete
	fileError := ioutil.WriteFile("../../testdata/tcertResponse2.json", []byte(tcertResponse), 0777)
	if fileError != nil {
		t.Fatalf("Problem in writing TCert Response file")
	}

}

func TestTCertrequestJSONMarshall(t *testing.T) {

	jsonBlob, err := ioutil.ReadFile("../../testdata/tcertrequestwithencryptedattributes.json")
	if err != nil {
		t.Fatalf("TestJOSNMarshall : Cannot read json request file")
	}
	batchRequest := &BatchRequest{}
	jsonError := json.Unmarshal(jsonBlob, batchRequest)
	if jsonError != nil {
		t.Errorf("Problem in JSON Marshalling = [%v]", jsonError)
	}

}

//Creates Signed RSA JSON  , Poupulate Signature Object , Validate Signature
func TestSignatureJSONMarshall(t *testing.T) {

	privKeyBuff, err := ioutil.ReadFile("../../testdata/rsaPrivateKey.pem")
	if err != nil {
		t.Fatalf("Unable to read private key PEM from file: [%v]", err)
	}
	rsaPrivateKey, err := crypto.GetPrivateKey(privKeyBuff)
	if err != nil {
		t.Fatalf("Unable to get private key: [%v]", err)
	}

	certBuff, certErr := ioutil.ReadFile("../../testdata/rsaCertificate.pem")
	if certErr != nil {
		t.Fatalf("Error reading certificate PEM file: %v", certErr)
	}

	jsonString := crypto.ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")
	signatureJSON := crypto.ConvertJSONFileToJSONString("../../testdata/signature.json")

	cert := base64.StdEncoding.EncodeToString(certBuff)
	signedJSON, signError := crypto.RSASignJSON(jsonString, "SHA2_384", signatureJSON, rsaPrivateKey.(*rsa.PrivateKey), cert)

	if signError != nil {
		t.Fatalf("json sign error : [%v]", signError)
	}

	signature := &crypto.Signature{}
	jsonError := json.Unmarshal([]byte(signedJSON), signature)
	if jsonError != nil {
		t.Fatalf("Signature json Marhalling failed with error\t [%v]", jsonError)
	}

	certificate, _ := base64.StdEncoding.DecodeString(signature.Certificate)

	_, error := crypto.GetCertificate(certificate)
	if error != nil {
		t.Fatalf("Cannot create EC Certificate \t [%v]", error)
	}

}
