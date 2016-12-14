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
	// Number of TCerts in the batch.
	// If more are requested than the MaxBatchSize, only MaxBatchSize will be returned.
	Count uint `json:"count"`
	// Set of attribute names whose names and values are to be placed in all tcerts
	// of the issued batch of tcerts
	AttrNames []string `json:"attrNames,omitempty"`
	// Certificate Validity Period.  If specified, the value used
	// is the minimum of this value and the configured validity period
	// of the TCert manager.
	ValidityPeriod time.Duration `json:"validityPeriod,omitempty"`
	//AttrEncryption denotes whether to encrypt attribute values or not
	AttrEncryption bool `json:"attrEncryption,omitempty"`
	// PreKey to be used for key derivation purposes.
	PreKey string `json:"prekey"`
	// The attribute name and values that are to be inserted in the issued tcerts.
	Attrs []Attribute `json:"attrs,omitempty"`
}

// GetBatchResponse is the response from the GetBatch API
type GetBatchResponse struct {
	ID     *big.Int  `json:"id"`
	TS     time.Time `json:"ts"`
	Key    []byte    `json:"key"`
	TCerts []TCert   `json:"tcerts"`
}

// TCert contains an issued transaction certificate
type TCert struct {
	Cert []byte            `json:"cert"`
	Keys map[string][]byte `json:"keys,omitempty"` //base64 encoded string as value
}

// Attribute is a single attribute name and value
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
