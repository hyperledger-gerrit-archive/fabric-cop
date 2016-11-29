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

import crypto "github.com/hyperledger/fabric-cop/lib/crypto"

// BatchRequest struct contains input to the TCert Generation
type BatchRequest struct {
	//Uid of the user making TCERT request.Optional field
	UID string `json:"uid,omitempty"`
	//Pre Key to be used for Key Derivation purposes. Required Field
	RootPreKey string `json:"RootPreKey"`
	//Number of TCerts in the batch.This is set to 1 , if this filed is absent.Required field
	Count int `json:"Num"`
	//Set of Attributes that are passed
	AttrNames []string `json:"attrNames,omitempty"`
	//Set of attributes that needs to be inserted in tcert. Optional field
	AttributeSet []Attribute `json:"AttributeSet,omitempty"`
	//Certificate Validity Period in the unit of hours.Optional Field.This value will be read from default config , if it is not present in the request
	ValidityPeriod int `json:"validityPeriod,omitempty"`
	//AttributeEncryptionEbabled , when set to true , encrypts attributes that are passed. Required field
	AttributeEncryptionEbabled bool `json:"attribute-encryption_enabled,omitempty"`
	//CertificateRequestData Contains CSR data. Optional field
	CertificateRequestData crypto.CSRData `json:"CertificateRequestData,omitempty"`
}

// Attribute struct containing Attributes that needs to be passed in the tcert
type Attribute struct {
	AttributeName  string `json:"AttributeName"`
	AttributeValue string `json:"AttributeValue"`
}
