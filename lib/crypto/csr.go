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

//CSRData contains Certificate Request Data
type CSRData struct {
	Country          string `json:"C,omitempty"`
	Locality         string `json:"L,omitempty"`
	Organization     string `json:"O,omitempty"`
	State            string `json:"ST,omitempty"`
	OrganizationUnit string `json:"OU,omitempty"`
	CommonName       string `json:"CN,omitempty"`
	ValidityPeriod   int    `json:"validityPeriod,omitempty"`
}

//Signature contains certificate and EC Signature and RSA Signature Data
type Signature struct {
	Certificate  string       `json:"Certificate"`
	HashAlgo     string       `json:"HashAlgo"`
	ECSignature  *ECSignature `json:"ECSignature,omitempty"`
	RSASignature string       `json:"RSASignature,omitempty"`
}

//ECSignature contains R and S value of EC Signature
type ECSignature struct {
	R string `json:"R"`
	S string `json:"S"`
}
