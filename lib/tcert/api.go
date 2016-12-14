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
	"math/big"
	"time"
)

/*
 * This file contains definitions of the input and output to the TCert
 * library APIs.
 */

// GetBatchRequest defines input to the GetBatch API
type GetBatchRequest struct {
	//Number of TCerts in the batch.This is set to 1 , if this filed is absent.Required field
	Count int `json:"Num"`
	//Set of Attributes that are passed
	AttrNames []string `json:"attrNames,omitempty"`
	// Certificate Validity Period.  See golang's time.ParseDuration for format
	// If not specified, use the manager's default value.
	ValidityPeriod string `json:"validityPeriod,omitempty"`
	//AttributeEncryptionEnabled denotes whether encrypt attributes or not
	AttributeEncryptionEnabled bool `json:"attribute-encryption_enabled,omitempty"`
	//Pre Key to be used for Key Derivation purposes. Required Field
	RootPreKey string
	// Set of attributes that needs to be inserted in tcert.
	AttributeSet []Attribute
}

// GetBatchResponse is the response from the GetBatch API
type GetBatchResponse struct {
	ID    *big.Int  `json:"id"`
	TS    time.Time `json:"ts"`
	Key   []byte    `json:"key"`
	Certs []TCert   `json:"TCerts"`
}

// TCert contains an issued transaction certificate
type TCert struct {
	Cert []byte            `json:"TCert"`
	Keys map[string][]byte `json:"keys,omitempty"` //base64 encoded string as value
}

// Attribute is a single attribute name and value
type Attribute struct {
	Name  string
	Value string
}
