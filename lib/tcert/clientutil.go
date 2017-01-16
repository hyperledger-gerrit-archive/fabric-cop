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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
)

//Need to put log statement , will use Golang Log
var (
	attributeSeparator      = "#"
	attributeIndexIdentifer = "->"
	attributeBaseIdentifier = 9
)

// GetAttributesFromTCert returns attributeList from TCert
// @keys : Map containing attribute decryption key
// @returns : Array of Attributes with name/value pair
func GetAttributesFromTCert(certBuf []byte, keys map[string][]byte) ([]Attribute, error) {

	if certBuf == nil {
		return nil, errors.New("Cert is nil")
	}
	cert, error := GetCertificate(certBuf)
	if error != nil {
		return nil, errors.New("Certificate cannot be created")
	}
	//Get Extension
	extraExtension := cert.Extensions
	extraExtensionLength := len(extraExtension)
	var extension pkix.Extension
	var id asn1.ObjectIdentifier
	var critical bool
	var headerValue []byte
	//var attrs []Attribute
	for i := 0; i < extraExtensionLength; i++ {
		extension = extraExtension[i]
		id = extension.Id
		critical = extension.Critical
		if id.Equal(TCertAttributesHeaders) && !critical {
			headerValue = extension.Value

			attrs, error := processAttributeHeader(string(headerValue), extraExtension, keys)
			if error != nil {
				log.Println("Attributes cannot be retrieved")
				return nil, errors.New("Attributes cannot be retrieved")
			}
			return attrs, nil
		}
	}

	return nil, nil
}

// processAttributeHeader processes header attribute set in the certificate
// @headerValue : Attribute header value
// @extension  :  Tcert Certificate Extension
// @keys : Map containing attribute decryption key
//@returns : Array of Attributes with name/value pair
func processAttributeHeader(headerValue string, extension []pkix.Extension, keys map[string][]byte) ([]Attribute, error) {

	if len(headerValue) == 0 {
		return nil, errors.New("Header Value is not passed")
	}

	attributeBlock := strings.Split(headerValue, attributeSeparator)
	attributeBlockLength := len(attributeBlock)
	if attributeBlockLength == 0 {
		return nil, errors.New("Attributes are not present in the cert")
	}

	var attributeName, attributeValue, attributeIdentifierString, errorMessage string
	var attribute []string
	var attributeIdentifier, sliceLength int
	var err error
	var shouldDecrypt, isKeyNil bool
	var attrBuf []byte

	if keys == nil {
		isKeyNil = true
	}
	var attrs []Attribute
	for i := 0; i < attributeBlockLength; i++ {
		if attributeBlock[i] != "" {
			attribute = strings.Split(attributeBlock[i], attributeIndexIdentifer)
			attributeName = attribute[0]
			if (keys[attributeName] != nil) && !isKeyNil {
				shouldDecrypt = true
			}
			attributeIdentifierString = attribute[1]
			attributeIdentifier, err = strconv.Atoi(attributeIdentifierString)
			if err != nil {
				errorMessage = fmt.Sprintf("String to Integer conversion failed with error : [%v]", err)
				return nil, errors.New(errorMessage)
			}

			attributeValue = getExtensionValueFromCert(asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, attributeIdentifier + attributeBaseIdentifier}, extension)
			if shouldDecrypt {
				attrBuf, err = CBCPKCS7Decrypt(keys[attributeName], []byte(attributeValue))
				if err != nil {
					errorMessage = fmt.Sprintf("The attribute value for [%s] cannot be decrypted", attributeName)
					log.Println(errorMessage)
					return nil, errors.New(errorMessage)
				}
				sliceLength = len(attrBuf) - 16
				attributeValue = string(attrBuf[:sliceLength])
			}
			attrs = append(attrs, Attribute{attributeName, attributeValue})
		}
	}
	log.Println("Attribute List Created")
	return attrs, nil
}

// Given an ASN , it returns extension value
func getExtensionValueFromCert(asnID asn1.ObjectIdentifier, extensions []pkix.Extension) string {
	noOfExtensions := len(extensions)
	var extension pkix.Extension
	var id asn1.ObjectIdentifier
	var critical bool
	//var headerValue []byte
	var attrValue string

	for i := 0; i < noOfExtensions; i++ {
		extension = extensions[i]
		id = extension.Id
		critical = extension.Critical

		if id.Equal(asnID) && !critical {
			attrValue = string(extension.Value)
			return attrValue
		}
	}
	return ""
}

// GetAttributeFromTCertResponse returns attributes
// from TCert Response. Intropspects only first certificate
// as same attribute list will be there in each certificate
func GetAttributeFromTCertResponse(tcertBatch *GetBatchResponse) ([]Attribute, error) {
	if tcertBatch == nil {
		return nil, errors.New("TCert batch is nil")
	}
	tcerts := tcertBatch.TCerts
	if len(tcerts) == 0 {
		return nil, errors.New("TCert Batch is nil")
	}

	// Reading only 1 TCert as Attributes will be the same in all TCerts
	tcert := tcerts[0]
	cert := tcert.Cert

	keys := tcert.Keys

	attribute, error := GetAttributesFromTCert(cert, keys)
	if error != nil {
		return nil, fmt.Errorf("Attribute retrieval failed with Error : [%v]", error)
	}

	return attribute, nil
}
