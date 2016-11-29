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

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
)

const (
	testName = "CertificateTest"
)

/****************  Has been added for testing purposes *********/
// BatchRequest struct contains input to the TCert Generation
type BatchRequest struct {
	//Uid of the user making TCERT request.Optional field
	UID string `json:"uid,omitempty"`
	//Pre Key to be used for Key Derivation purposes. Required Field
	RootPreKey string `json:"RootPreKey"`
	//Number of TCerts in the batch.This is set to 1 , if this filed is absent.Required field
	Count int `json:"Num"`
	//Set of attributes that needs to be inserted in tcert. Optional field
	AttributeSet []Attribute `json:"AttributeSet,omitempty"`
	//Certificate Validity Period in the unit of hours.Optional Field.This value will be read from default config , if it is not present in the request
	ValidityPeriod int `json:"validityPeriod,omitempty"`
	//AttributeEncryptionEbabled , when set to true , encrypts attributes that are passed. Required field
	AttributeEncryptionEbabled bool `json:"attribute-encryption_enabled,omitempty"`
	//CertificateRequestData Contains CSR data. Optional field
	CertificateRequestData CSRData `json:"CertificateRequestData,omitempty"`
}

// Attribute struct containing Attributes that needs to be passed in the tcert
type Attribute struct {
	AttributeName  string `json:"AttributeName"`
	AttributeValue string `json:"AttributeValue"`
}

/*************************  Has been added for testing purposes *******************/

func TestCAIssuedCert(t *testing.T) {

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate EC Key Pair")
	}

	extraExtensionData := []byte("extra extension")
	extraExtensionData2 := []byte("extra extension2")
	var pkixExtension = []pkix.Extension{
		{
			Id:    []int{1, 2, 3, 4},
			Value: extraExtensionData,
		},

		{
			Id:       []int{1, 2, 3, 4},
			Value:    extraExtensionData2,
			Critical: true,
		},
	}

	jsonBlob, err := ioutil.ReadFile("../../testdata/tcertrequestwithoutattr.json")
	if err != nil {
		t.Fatalf("TestCAIssuedCert : Cannot read request json file")
	}
	batchRequest := &BatchRequest{}
	jsonError := json.Unmarshal(jsonBlob, batchRequest)
	if jsonError != nil {
		t.Errorf("unable to marshall request [%v]", jsonError)
	}
	uid := batchRequest.UID

	certSpec, error := ParseCertificateRequest(&batchRequest.CertificateRequestData, uid, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
	if error != nil {
		t.Fatalf("CSR did not contain mandatory data -- [%v]", error)
	}

	rawcert, certError := NewCertificateFromSpec(certSpec)
	if certError != nil {
		t.Fatalf("cannot generate Cert ")
	}
	if rawcert != nil {

		err := ioutil.WriteFile("../../testdata/testCert.pem", rawcert, 0777)
		if err != nil {
			t.Fatalf("Problem in writing file")
		}
	}
}

//TestInvalidCertRequest is negative test case for absence of mandatory field in CSR request
func TestInvalidCertRequest(t *testing.T) {

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate EC Key Pair")
	}

	extraExtensionData := []byte("extra extension")
	extraExtensionData2 := []byte("extra extension2")
	var pkixExtension = []pkix.Extension{
		{
			Id:    []int{1, 2, 3, 4},
			Value: extraExtensionData,
		},

		{
			Id:       []int{1, 2, 3, 4},
			Value:    extraExtensionData2,
			Critical: true,
		},
	}

	jsonBlob, err := ioutil.ReadFile("../../testdata/tcertrequestwithinvalidcsr.json")
	if err != nil {
		t.Fatalf("TestInvalidCertRequest : Cannot read json file from file system")
	}
	batchRequest := &BatchRequest{}
	jsonError := json.Unmarshal(jsonBlob, batchRequest)
	if jsonError != nil {
		t.Errorf("Input request cannot be marshalled to json with error [%v]", jsonError)
	}
	uid := batchRequest.UID

	certSpec, error := ParseCertificateRequest(&batchRequest.CertificateRequestData, uid, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
	if error == nil {
		t.Fatalf("Certificate Creation should have failed")
	} else {
		t.Logf("cert error = [+%v]", error)
	}

	if certSpec != nil {

		rawcert, certError := NewCertificateFromSpec(certSpec)
		if certError != nil {
			t.Fatalf("cannot generate Cert ")
		}
		if rawcert != nil {

			err := ioutil.WriteFile("../../testdata/testCert.der", rawcert, 0777)
			if err != nil {
				t.Fatalf("Problem in writing file")
			}
		}
	}
}

func TestCertWithUidInRequest(t *testing.T) {

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate EC Key Pair")
	}

	extraExtensionData := []byte("extra extension")
	extraExtensionData2 := []byte("extra extension2")
	var pkixExtension = []pkix.Extension{
		{
			Id:    []int{1, 2, 3, 4},
			Value: extraExtensionData,
		},

		{
			Id:       []int{1, 2, 3, 4},
			Value:    extraExtensionData2,
			Critical: true,
		},
	}

	jsonBlob, err := ioutil.ReadFile("../../testdata/tcertrequestwithuid.json")
	if err != nil {
		t.Fatalf("TestCertWithUidInRequest : Cannot read test json file")
	}
	batchRequest := &BatchRequest{}
	jsonError := json.Unmarshal(jsonBlob, batchRequest)
	if jsonError != nil {
		t.Errorf("Marshalling error = [%v]", jsonError)
	}
	uid := batchRequest.UID

	certSpec, error := ParseCertificateRequest(&batchRequest.CertificateRequestData, uid, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)

	if error != nil {
		t.Fatalf("CSR did not contain mandatory data -- [%v]", error)
	}

	rawcert, certError := NewCertificateFromSpec(certSpec)
	if certError != nil {
		t.Fatalf("cannot generate Cert ")
	}
	if rawcert != nil {

		err := ioutil.WriteFile("../../testdata/testuid.pem", rawcert, 0777)
		if err != nil {
			t.Fatalf("Problem in writing file")
		}
	}
}

//TestCertExtension reads certificate extension
func TestCertExtension(t *testing.T) {

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate EC Key Pair")
	}

	extraExtensionData := []byte("extra extension")
	extraExtensionData2 := []byte("extra extension2")
	TCertEncTCertIndex := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	var pkixExtension = []pkix.Extension{
		{
			Id:    []int{1, 2, 3, 4},
			Value: extraExtensionData,
		},
		{
			Id:       TCertEncTCertIndex,
			Value:    extraExtensionData2,
			Critical: true,
		},
	}

	jsonBlob, err := ioutil.ReadFile("../../testdata/tcertrequestwithoutattr.json")
	if err != nil {
		t.Fatalf("TestJOSNMarshall : Cannot read EC Private Key File")
	}
	batchRequest := &BatchRequest{}
	jsonError := json.Unmarshal(jsonBlob, batchRequest)
	if jsonError != nil {
		t.Errorf("JSON Marshalling error = [%v]", jsonError)
	}
	uid := batchRequest.UID

	certSpec, error := ParseCertificateRequest(&batchRequest.CertificateRequestData, uid, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
	if error != nil {
		t.Fatalf("CSR did not contain mandatory data -- [%v]", error)
	}

	rawcert, _ := NewCertificateFromSpec(certSpec)

	certificate, error := GetCertificate(rawcert)
	if error != nil {
		t.Fatalf("cannot get Certificate Object")
	}

	extensions := certificate.Extensions
	extensionsLength := len(extensions)
	var extensionValueField string
	for j := 0; j < extensionsLength; j++ {
		id := extensions[j].Id
		if id.Equal(TCertEncTCertIndex) && (extensions[j].Critical) {
			extensionValueField = string(extensions[j].Value)
		}
	}
	if extensionValueField != string(extraExtensionData2) {
		t.Fatalf("cannot retrieve certificate extension field")
	}
}

//TestCertEncryptedExtension tests Encrypted Certificate field
func TestCertEncryptedExtension(t *testing.T) {
	//jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate EC Key Pair")
	}

	extraExtensionData := []byte("extra extension")
	extraExtensionData2 := []byte("1111111111111111111111111")
	TCertEncTCertIndex := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}

	key := make([]byte, AESKeyLength)
	rand.Reader.Read(key)

	encrypted, encErr := CBCPKCS7Encrypt(key, extraExtensionData2)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %s", extraExtensionData2, encErr)
	}
	var pkixExtension = []pkix.Extension{
		{
			Id:    []int{1, 2, 3, 4},
			Value: extraExtensionData,
		},
		{
			Id:       TCertEncTCertIndex,
			Value:    encrypted,
			Critical: true,
		},
	}

	jsonBlob, err := ioutil.ReadFile("../../testdata/tcertrequestwithoutattr.json")
	if err != nil {
		t.Fatalf("TestCertEncryptedExtension : Cannot read EC TCert json file")
	}
	batchRequest := &BatchRequest{}
	jsonError := json.Unmarshal(jsonBlob, batchRequest)
	if jsonError != nil {
		t.Errorf("JSON Marshalling error = [%v]", jsonError)
	}

	uid := batchRequest.UID
	certSpec, error := ParseCertificateRequest(&batchRequest.CertificateRequestData, uid, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
	if error != nil {
		t.Fatalf("CSR did not contain mandatory data -- [%v]", error)
	}

	rawcert, _ := NewCertificateFromSpec(certSpec)

	certificate, error := GetCertificate(rawcert)
	if error != nil {
		t.Fatalf("cannot get Certificate Object")
	}

	extensions := certificate.Extensions
	extensionsLength := len(extensions)
	var extensionValueField string
	for j := 0; j < extensionsLength; j++ {
		id := extensions[j].Id
		if id.Equal(TCertEncTCertIndex) && (extensions[j].Critical) {
			decryptedValue, decryptEror := CBCPKCS7Decrypt(key, extensions[j].Value)
			if decryptEror != nil {
				t.Fatalf("cannot decrypt [%v]", decryptEror)
			}
			extensionValueField = string(decryptedValue)

		}
	}
	if extensionValueField != string(extraExtensionData2) {
		t.Fatalf("cannot retrieve certificate extension field")
	}
}
