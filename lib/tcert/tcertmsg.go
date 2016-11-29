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

//CreateSetResp  Message contains TCert Responses
type CreateSetResp struct {
	Certs *CertSet `json:"TCertSet,omitempty"`
}

//CertSet contains tcer set
type CertSet struct {
	ID    string  `json:"id,omitempty"`
	Key   []byte  `json:"key,omitempty"`
	Certs []TCert `json:"TCerts,omitempty"` //Base64 encoded string
}

//TCert structure contains TCert structure
type TCert struct {
	Cert string            `json:"TCert,omitempty"` //base64 encoded string
	Keys map[string][]byte `json:"keys,omitempty"`  //base64 encoded string as value
}

//Key contains TCert Key and Certififate
type Key struct {
	privateKey  []byte
	certificate []byte
}
