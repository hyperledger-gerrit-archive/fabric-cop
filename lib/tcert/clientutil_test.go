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
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestGetUnecnryptedAttrFromCertAndTCertResponse(t *testing.T) {

	certBuff, err := ioutil.ReadFile("../../testdata/tcertwithunencryptedattr.pem")
	if err != nil {
		t.Errorf("Reading Cert file from directory failed with error : [%v]", err)
	}

	attr, error := GetAttributesFromTCert(certBuff, nil)
	if error != nil {
		t.Errorf("GetAttributeFromCert failed with error : [%v]", error)
	}

	var noOfAttribute int
	noOfAttribute = len(attr)

	if (noOfAttribute == 0) || (noOfAttribute != 2) {
		t.Error("Attribute was not found in the TCert")
	}
	if error != nil {
		t.Errorf("GetAttributeFromCert failed with error : [%v]", error)
	}

	//Read from TCert Response
	tcertJSONResponse, err := ioutil.ReadFile("../../testdata/tcert_response_unenc_attr.json")
	if err != nil {
		t.Errorf("Reading TCert JSON response from directory failed with error : [%v]", err)
	}
	//Perform JSON unmarshalling
	batchResponse := &GetBatchResponse{}
	_ = json.Unmarshal(tcertJSONResponse, batchResponse)
	attrFromTCertResponse, error := GetAttributeFromTCertResponse(batchResponse)

	if error != nil {
		t.Errorf("GetAttributeFromCert failed with error : [%v]", error)
	}

	noOfAttribute = len(attrFromTCertResponse)

	if (noOfAttribute == 0) || (noOfAttribute != 2) {
		t.Error("Attribute was not found in the TCert")
	}
	if error != nil {
		t.Errorf("GetAttributeFromCert failed with error : [%v]", error)
	}

	//Test for Key pair Generated at client
	tcertJSONResponse, err = ioutil.ReadFile("../../testdata/tcert_response_unenc_attr_nokey.json")
	if err != nil {
		t.Errorf("Reading TCert JSON response from directory failed with error : [%v]", err)
	}

	_ = json.Unmarshal(tcertJSONResponse, batchResponse)
	attrFromTCertResponse, error = GetAttributeFromTCertResponse(batchResponse)
	if error != nil {
		t.Errorf("GetAttributeFromCert failed with error : [%v]", error)
	}

	noOfAttribute = len(attrFromTCertResponse)

	if (noOfAttribute == 0) || (noOfAttribute != 2) {
		t.Error("Attribute was not found in the TCert")
	}
	if error != nil {
		t.Errorf("GetAttributeFromCert failed with error : [%v]", error)
	}

}

func TestGetEcnryptedAttrFromCert(t *testing.T) {

	tcertJSONResponse, err := ioutil.ReadFile("../../testdata/tcert_response_enc_attr.json")
	if err != nil {
		t.Errorf("Reading TCert JSON response from directory failed with error : [%v]", err)
	}
	//Perform JSON unmarshalling
	batchResponse := &GetBatchResponse{}
	_ = json.Unmarshal(tcertJSONResponse, batchResponse)
	attr, error := GetAttributeFromTCertResponse(batchResponse)

	if error != nil {
		t.Errorf("GetAttributeFromCert failed with error : [%v]", error)
	}

	noOfAttribute := len(attr)

	if (noOfAttribute == 0) || (noOfAttribute != 2) {
		t.Error("Attribute was not found in the TCert")
	}
	if error != nil {
		t.Errorf("GetAttributeFromCert failed with error : [%v]", error)
	}

}
