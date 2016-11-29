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
	"encoding/base64"
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

	tcertResponse, error := GetCertificateSet(jsonString, signedJSON)
	if error == nil {
		t.Fatalf("Problem in creating TCert Response")
	}
	//Need to delete file later on when testing is complete
	fileError := ioutil.WriteFile("../../testdata/tcertResponse1.json", []byte(tcertResponse), 0777)
	if fileError != nil {
		t.Fatalf("Problem in writing TCert Response file")
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

/*
func TestNum(t *testing.T){
	  fmt.Println("111111")
    jsonString := ConvertJSONFileToJSONString("TCertRequest.json")
		fmt.Println(jsonString)
    num := ReadJSONAsMapString(jsonString, "TCertBatchRequest.Num")
		fmt.Println(num)
}
*/

func TestArbit(t *testing.T) {

	raw, _ := base64.StdEncoding.DecodeString("MIIC8jCCApigAwIBAgIQLIuvu6AMTnOvbmFJIr63/TAKBggqhkjOPQQDAzBpMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEfMB0GA1UEChMWSW50ZXJuZXQgV2lkZ2V0cywgSW5jLjEMMAoGA1UECxMDV1dXMB4XDTE2MTEyODE3NDE0MVoXDTE2MTEyODE4NDE0MVowWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk5DMQwwCgYDVQQHEwNSVFAxDDAKBgNVBAoTA0lCTTEMMAoGA1UECxMDV1dXMRUwEwYDVQQDEwx3d3cuZG9pdC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQTu+3FxLKgCaKpe6hfIKwx997UE/pKKIhakrGhY4HwvaRtHR+F4P/UoIM4BbZOG1lNiJJaBVeX8oYo0PdK6FXfo4IBLjCCASowDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwDQYDVR0OBAYEBAECAwQwHwYDVR0jBBgwFoAUbqPcLW3eXQLZisZuLQwDdpB1/gowOgYGKgMEBQYKBDCbVrdhzmPdE3c9D/L0NoI9QsIOKtV0lUHSYGwnr0QDwaP4v29pIrZAHp/ZIYW1WKEwTQYGKgMEBQYHAQH/BEB7CQR1xznlkClq88zI1beHbJcgsjfs2qGWU0o/S9oUFZLK2qasmgJCRDSZqfaElQiBGRcAHH5md4mI+XSEYM3kMDoGBioDBAUGCAQwyjjeM9HHQy67lQRiCMNlzlsAtwPfNyMCWoZ+XRPWK0YwCzRN6PxJJ28JfF7Z8Lx0MBMGBioDBAUGCQQJaEFQUFktPjEjMAoGCCqGSM49BAMDA0gAMEUCIQDNPbA1LvxrHD4ICNDta8wP6HS3ZNQ8EDETGFaGuMOAcgIgQQAI2xsw11LlmchUMJ+i3Ptq44cOgIidKLS7tcds4Mo=")
	fileError := ioutil.WriteFile("../../testdata/tcertResponse.der", raw, 0777)
	if fileError != nil {
		t.Fatalf("Problem in writing TCert Response file")
	}
}
