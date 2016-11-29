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
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

const (
	testName = "CertificateTest"
)

func TestCAIssuedCert(t *testing.T) {

	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")

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

	certSpec, error := ParseCertificateRequest(jsonString, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
	if error != nil {
		t.Fatalf("CSR did not contain mandatory data -- [%v]", error)
	}

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

//TestInvalidCertRequest is negative test case for absence of mandatory field in CSR request
func TestInvalidCertRequest(t *testing.T) {

	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequestwithinvalidcsr.json")

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

	certSpec, error := ParseCertificateRequest(jsonString, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
	if error == nil {
		t.Fatalf("Certificate Creation should have failed")
	} else {
		fmt.Printf("cert error = [+%v]", error)
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

	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequestwithuid.json")

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

	certSpec, error := ParseCertificateRequest(jsonString, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
	if error != nil {
		t.Fatalf("CSR did not contain mandatory data -- [%v]", error)
	}

	rawcert, certError := NewCertificateFromSpec(certSpec)
	if certError != nil {
		t.Fatalf("cannot generate Cert ")
	}
	if rawcert != nil {

		err := ioutil.WriteFile("../../testdata/testuid.der", rawcert, 0777)
		if err != nil {
			t.Fatalf("Problem in writing file")
		}
	}
}

//TestCertExtension reads certificate extension
func TestCertExtension(t *testing.T) {
	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")

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

	certSpec, error := ParseCertificateRequest(jsonString, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
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
	jsonString := ConvertJSONFileToJSONString("../../testdata/tcertrequest.json")

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

	certSpec, error := ParseCertificateRequest(jsonString, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
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
