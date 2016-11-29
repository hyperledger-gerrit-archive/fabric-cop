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
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"time"

	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"

	"github.com/cloudflare/cfssl/log"
	"github.com/stretchr/stew/objects"
)

//ReadJSONAsMapString reads keyvalue from  JSON Strings based on the JSON string path
func ReadJSONAsMapString(jsonString string, stringLocator string) (string, error) {
	jsonMap, error := objects.NewMapFromJSON(jsonString)
	if error != nil {
		log.Errorf("jsonProcessor : The json string passed \n ---------- [%s] is malformed", jsonString)

		return "", error
	}

	keyValue := jsonMap.Get(stringLocator)
	if keyValue == nil {
		return "", errors.New("keyValue is empty")
	}

	return keyValue.(string), nil
}

//ReadMapValue reads map value and returns value for the map
func ReadMapValue(jsonMap objects.Map, key string) string {

	value := jsonMap.Get(key)
	if value == nil {
		return ""
	}
	return value.(string)
}

//GetAttributes get attributes from jsonString
//@jsonString : jsonString containing Attributes
//@ returns : map containing attribute name as Key and Attribute Value as value
func GetAttributes(jsonString string) map[string]string {
	if (jsonString == "") || (len(jsonString) == 0) {
		return nil
	}

	jsonMap, _ := objects.NewMapFromJSON(jsonString)
	stringLocator := "TCertBatchRequest.AttributeSet"
	var keyValue = jsonMap.Get(stringLocator)
	valueMap := make(map[string]string)
	if keyValue == nil {
		return nil
	}
	for i := range keyValue.([]interface{}) {
		arribute := keyValue.([]interface{})[i]

		attributeName := arribute.(map[string]interface{})["AttributeName"].(string)
		attributeValue := arribute.(map[string]interface{})["AttributeValue"].(string)
		valueMap[attributeName] = attributeValue
	}

	return valueMap

}

//ParseCertificateRequest takes certificate request from JSON and Creates CertificateSpec object
/*
func ParseCertificateRequest(jsonstring string, serialNumber *big.Int, pub interface{}, usage x509.KeyUsage, opt []pkix.Extension) *CertificateSpec {

	stringLocator := "TCertBatchRequest.CertificateRequestData"
	jsonMap, _ := objects.NewMapFromJSON(jsonstring)

	//Validity Period is in the units of hours
	certSpec := new(CertificateSpec)
	certSpec.commonName = jsonMap.Get(stringLocator + ".CN").(string)

	certSpec.country = jsonMap.Get(stringLocator + ".C").(string)
	certSpec.State = jsonMap.Get(stringLocator + ".ST").(string)
	certSpec.locality = jsonMap.Get(stringLocator + ".L").(string)
	certSpec.Organization = jsonMap.Get(stringLocator + ".O").(string)
	certSpec.OrganizationUnit = jsonMap.Get(stringLocator + ".OU").(string)
	validityPeriod := jsonMap.Get(stringLocator + ".validityPeriod").(float64)

	NotBefore := time.Now()
	NotAfter := NotBefore.Add(time.Duration(validityPeriod) * time.Hour)
	certSpec.NotBefore = NotBefore
	certSpec.NotAfter = NotAfter

	certSpec.serialNumber = serialNumber
	certSpec.pub = pub
	certSpec.usage = usage
	certSpec.ext = &opt

	return certSpec
}
*/

//isCertRequestValid looks for required attributes necessary for certificate creartion
//@jsonString/map corresponds to TCertRequest
//@stringLocator is the path to cert Object in the request json file
func isCertRequestValid(requestJSONMap objects.Map, stringLocator string) error {

	certMandatoryFields := ConvertJSONFileToJSONString("mandatortycertdata.json")
	mandatoryCertJosnMap, _ := objects.NewMapFromJSON(certMandatoryFields)

	var keyValue = mandatoryCertJosnMap.Get("CertificateMandatoryFieilds")
	var errorBuffer bytes.Buffer

	//madatoybuffer.WriteString("CSR Data mandato \n")
	isValidCSRequst := true
	for i := range keyValue.([]interface{}) {
		certfields := keyValue.([]interface{})[i].(string)
		switch certfields {
		case "CN":
			errorBuffer.WriteString("CN/")
			if requestJSONMap.Get(stringLocator+".CN") == nil {
				isValidCSRequst = false
				break
			}
		case "O":
			errorBuffer.WriteString("O/")
			if requestJSONMap.Get(stringLocator+".O") == nil {
				isValidCSRequst = false
				break
			}
		case "OU":
			errorBuffer.WriteString("OU/")
			if requestJSONMap.Get(stringLocator+".OU") == nil {
				isValidCSRequst = false
				break
			}
		case "C":
			errorBuffer.WriteString("C/")
			if requestJSONMap.Get(stringLocator+".C") == nil {
				isValidCSRequst = false
				break
			}
		case "ST":
			errorBuffer.WriteString("ST/")
			if requestJSONMap.Get(stringLocator+".ST") == nil {
				isValidCSRequst = false
				break
			}
		case "L":
			errorBuffer.WriteString("L/")
			if requestJSONMap.Get(stringLocator+".L") == nil {
				isValidCSRequst = false
				break
			}
		case "validityPeriod":
			errorBuffer.WriteString("validityPeriod")
			if requestJSONMap.Get(stringLocator+".validityPeriod") == nil {
				isValidCSRequst = false
				break
			}

		}

	}
	if !isValidCSRequst {
		errorMessage := "One of madatory fields == " + errorBuffer.String() + "== for CSR request is missing."
		return errors.New(errorMessage)
	}
	return nil
}

// ParseCertificateRequest returns a *CertificateSpec
func ParseCertificateRequest(jsonstring string, serialNumber *big.Int, pub interface{}, usage x509.KeyUsage, opt []pkix.Extension) (*CertificateSpec, error) {

	NotBefore := time.Now()

	var expiryhrs float64

	var csrdataMap map[string]interface{}

	var tcertReqMap map[string]interface{}

	errtcert := json.Unmarshal([]byte(jsonstring), &tcertReqMap)

	if errtcert != nil {

		log.Fatal("Error unmarshalling tcertjson:", errtcert)

	}

	csrdataString := ConvertJSONFileToJSONString("csrdata.json")

	errcsr := json.Unmarshal([]byte(csrdataString), &csrdataMap)

	if errcsr != nil {

		log.Fatal("Error unmarshalling csrdataString:", errcsr)

	}

	stringLocator := "TCertBatchRequest.CertificateRequestData"

	jsonMap, _ := objects.NewMapFromJSON(jsonstring)

	UID, _ := jsonMap.Get("TCertBatchRequest.uid").(string)

	certSpec := new(CertificateSpec)

	if len(UID) > 0 {

		certSpec.commonName = csrdataMap["CN"].(string)

		certSpec.country = csrdataMap["C"].(string)

		certSpec.Organization = csrdataMap["O"].(string)

	} else {

		error := isCertRequestValid(jsonMap, stringLocator)
		if error != nil {
			log.Error(error)
			return nil, error
		}

		certSpec.commonName = ReadMapValue(jsonMap, stringLocator+".CN")
		certSpec.country = ReadMapValue(jsonMap, stringLocator+".C")
		certSpec.State = ReadMapValue(jsonMap, stringLocator+".ST")
		certSpec.locality = ReadMapValue(jsonMap, stringLocator+".L")
		certSpec.Organization = ReadMapValue(jsonMap, stringLocator+".O")
		certSpec.OrganizationUnit = ReadMapValue(jsonMap, stringLocator+".OU")
	}

	certSpec.serialNumber = serialNumber

	certSpec.pub = pub

	certSpec.usage = usage

	certSpec.ext = &opt

	var validityPeriodFromUserRequest float64
	validityPeriodFromUserRequest = jsonMap.Get(stringLocator + ".validityPeriod").(float64)

	if validityPeriodFromUserRequest > csrdataMap["ValidityPeriod"].(float64) {
		expiryhrs = csrdataMap["ValidityPeriod"].(float64)

	} else {

		expiryhrs = validityPeriodFromUserRequest

	}

	NotAfter := NotBefore.Add(time.Duration(expiryhrs) * time.Hour)
	certSpec.NotBefore = NotBefore

	certSpec.NotAfter = NotAfter

	return certSpec, nil

}

//IsAttributeEncryptionEnabled Gets encryption bool flag
func IsAttributeEncryptionEnabled(jsonstring string) bool {
	jsonMap, _ := objects.NewMapFromJSON(jsonstring)
	areAttributesEnctypted := jsonMap.Get("TCertBatchRequest.attribute-encryption_enabled").(bool)
	return areAttributesEnctypted
}

//ConvertJSONFileToJSONString converts a file of json format to a json string
func ConvertJSONFileToJSONString(jsonFileLocation string) string {
	buff, err := ioutil.ReadFile(jsonFileLocation)
	if err != nil {
		log.Fatal("ConvertJSONFileToJSONString : Error reading json file:", err)
	}
	var jsonString = string(buff)
	return jsonString
}

//WriteJSONToString takes a map as input and returns json map
func WriteJSONToString(jsonString string, valueMap map[string]string) string {
	jsonMap, _ := objects.NewMapFromJSON(jsonString)
	for key, value := range valueMap {
		_ = jsonMap.Set(key, value)
	}
	jsonOutString, _ := jsonMap.JSON()
	return jsonOutString
}

//WriteToJSON reads a file name from configfile and writes json file one at a time
func WriteToJSON(filePath string, cotentToAppend string) {

	_, err := os.Stat(filePath)
	if err != nil {
		_, createerr := os.Create(filePath)
		if createerr != nil {
			log.Fatal("Error creating file:", err)
		}
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal("Error opening file:", err)
	}

	defer f.Close()

	if _, err = f.WriteString(cotentToAppend + "\n"); err != nil {
		log.Fatal("Error writing json string:", err)
	}

}
