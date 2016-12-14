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
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"math/big"
	"strconv"

	"github.com/cloudflare/cfssl/log"
)

var (
	// TCertEncTCertIndex is the ASN1 object identifier of the TCert index.
	TCertEncTCertIndex = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}

	// TCertEncEnrollmentID is the ASN1 object identifier of the enrollment id.
	TCertEncEnrollmentID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 8}

	// TCertAttributesHeaders is the ASN1 object identifier of attributes header.
	TCertAttributesHeaders = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 9}

	// Padding for encryption.
	Padding = []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
)

// NewMgr is the constructor for a TCert manager
// @parameter template is the template certificate used when creating all tcerts
// @parameter caCert is used for extracting CA data to associate with issued certificates
// @parameter caKey is used for signing a certificate request
// @parameter validityPeriod is the duration that the issued certificate will be valid
//            unless the user requests a shorter validity period.
//            See golang's time.ParseDuration for the format of this string
func NewMgr(template, caCert *x509.Certificate, caKey interface{}, validityPeriod string) (*Mgr, error) {
	vp, err := time.ParseDuration(validityPeriod)
	if err != nil {
		return nil, err
	}
	mgr := new(Mgr)
	mgr.Template = template
	mgr.CACert = caCert
	mgr.CAKey = caKey
	mgr.ValidityPeriod = vp
	return mgr, nil
}

// Mgr is the manager for the TCert library
type Mgr struct {
	// Template is used when creating all tcerts
	Template *x509.Certificate
	// CACert is used for extracting CA data to associate with issued certificates
	CACert *x509.Certificate
	// CAKey is used for signing a certificate request
	CAKey interface{}
	// ValidityPeriod is the duration that the issued certificate will be valid
	// unless the user requests a shorter validity period.
	ValidityPeriod time.Duration
}

// GetBatch gets a batch of tcerts
// @parameter req Is the TCert batch request that flows over the wire from a client
// @parameter ecert Is the enrollment certificate of the caller (also sent over the wire) and validated
//            prior to calling this function.
func (tm *Mgr) GetBatch(req *GetBatchRequest, ecert *x509.Certificate) (*GetBatchResponse, error) {

	log.Debugf("GetBatch req=%+v", req)

	// Certs are valid for the min of requested and configured max
	vp := tm.ValidityPeriod
	if req.ValidityPeriod != "" {
		reqVP, err := time.ParseDuration(req.ValidityPeriod)
		if err != nil {
			return nil, err
		}
		if reqVP < vp {
			vp = reqVP
		}
	}

	// Clone the cert and update NotBefore and NotAfter based on validity period
	template := tm.Template
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(vp)
	template.IsCA = false
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.SubjectKeyId = []byte{1, 2, 3, 4}

	// Generate nonce for TCertIndex
	nonce := make([]byte, 16) // 8 bytes rand, 8 bytes timestamp
	rand.Reader.Read(nonce[:8])

	pub := ecert.PublicKey.(*ecdsa.PublicKey)

	mac := hmac.New(sha512.New384, []byte(createHMACKey()))
	raw, _ := x509.MarshalPKIXPublicKey(pub)
	mac.Write(raw)
	kdfKey := mac.Sum(nil)

	num := req.Count
	if num == 0 {
		num = 1
	}

	var set []TCert

	for i := 0; i < num; i++ {
		tcertid, uuidError := GenerateIntUUID()
		if uuidError != nil {
			log.Errorf("error in genrrating UUID [%v]", uuidError)
			return nil, errors.New("Problem in generating UUID")
		}
		// Compute TCertIndex
		tidx := []byte(strconv.Itoa(2*i + 1))
		tidx = append(tidx[:], nonce[:]...)
		tidx = append(tidx[:], Padding...)

		mac := hmac.New(sha512.New384, kdfKey)
		mac.Write([]byte{1})
		extKey := mac.Sum(nil)[:32]

		mac = hmac.New(sha512.New384, kdfKey)
		mac.Write([]byte{2})
		mac = hmac.New(sha512.New384, mac.Sum(nil))
		mac.Write(tidx)

		one := new(big.Int).SetInt64(1)
		k := new(big.Int).SetBytes(mac.Sum(nil))
		k.Mod(k, new(big.Int).Sub(pub.Curve.Params().N, one))
		k.Add(k, one)

		tmpX, tmpY := pub.ScalarBaseMult(k.Bytes())
		txX, txY := pub.Curve.Add(pub.X, pub.Y, tmpX, tmpY)
		txPub := ecdsa.PublicKey{Curve: pub.Curve, X: txX, Y: txY}

		// Compute encrypted TCertIndex
		encryptedTidx, encryptErr := CBCPKCS7Encrypt(extKey, tidx)
		if encryptErr != nil {
			return nil, encryptErr
		}

		extensions, ks, extensionErr := generateExtensions(tcertid, encryptedTidx, ecert, req)

		if extensionErr != nil {
			return nil, extensionErr
		}

		template.PublicKey = txPub
		template.Extensions = extensions
		template.ExtraExtensions = extensions
		template.SerialNumber = tcertid

		raw, err := x509.CreateCertificate(rand.Reader, template, tm.CACert, &txPub, tm.CAKey)
		if err != nil {
			return nil, fmt.Errorf("Failed in tcert x509.CreateCertificate: %s", err)
		}

		pem := ConvertDERToPEM(raw, "CERTIFICATE")

		set = append(set, TCert{pem, ks})
	}

	tcertID := GenNumber(big.NewInt(20))
	tcertResponse := &GetBatchResponse{tcertID, time.Now(), kdfKey, set}

	return tcertResponse, nil

}

/**
*  Create HMAC Key
*  returns HMAC String
*  Persistence Part is not being implemented yet
 */
func createHMACKey() string {
	//var cooked string
	key := make([]byte, 49)
	rand.Reader.Read(key)
	var cooked = base64.StdEncoding.EncodeToString(key)
	return cooked

}

// Generate encrypted extensions to be included into the TCert (TCertIndex, EnrollmentID and attributes).
func generateExtensions(tcertid *big.Int, tidx []byte, enrollmentCert *x509.Certificate, batchRequest *GetBatchRequest) ([]pkix.Extension, map[string][]byte, error) {
	// For each TCert we need to store and retrieve to the user the list of Ks used to encrypt the EnrollmentID and the attributes.
	ks := make(map[string][]byte)
	attributeSet := batchRequest.AttributeSet
	extensions := make([]pkix.Extension, len(attributeSet))

	preK1 := batchRequest.RootPreKey
	//mac := hmac.New(primitives.GetDefaultHash(), preK1)
	mac := hmac.New(sha512.New384, []byte(preK1))
	mac.Write(tcertid.Bytes())
	preK0 := mac.Sum(nil)

	// Compute encrypted EnrollmentID
	mac = hmac.New(sha512.New384, preK0)
	mac.Write([]byte("enrollmentID"))
	enrollmentIDKey := mac.Sum(nil)[:32]

	//enrollmentID := []byte(enrollmentCert.Subject.CommonName)
	enrollmentID := []byte(GetEnrollmentIDFromCert(enrollmentCert))
	enrollmentID = append(enrollmentID, Padding...)

	encEnrollmentID, err := CBCPKCS7Encrypt(enrollmentIDKey, enrollmentID)
	if err != nil {
		return nil, nil, err
	}

	// save k used to encrypt EnrollmentID
	ks["enrollmentId"] = enrollmentIDKey

	attributeIdentifierIndex := 9
	count := 0
	attributesHeader := make(map[string]int)
	// Encrypt and append attributes to the extensions slice

	var AttributeName, AttributeValue string
	//for AttributeName, AttributeValue := range attributes {
	for i := 0; i < len(attributeSet); i++ {
		count++
		AttributeName = attributeSet[i].Name
		AttributeValue = attributeSet[i].Value

		value := []byte(AttributeValue)

		//Save the position of the attribute extension on the header.
		attributesHeader[AttributeName] = count

		if batchRequest.AttributeEncryptionEnabled {
			mac = hmac.New(sha512.New384, preK0)
			mac.Write([]byte(AttributeName))
			attributeKey := mac.Sum(nil)[:32]

			value = append(value, Padding...)
			value, err = CBCPKCS7Encrypt(attributeKey, value)
			if err != nil {
				return nil, nil, err
			}

			// save k used to encrypt attribute
			//Base 64 encode attribute Key
			ks[AttributeName] = attributeKey
		}

		// Generate an ObjectIdentifier for the extension holding the attribute
		TCertEncAttributes := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, attributeIdentifierIndex + count}

		// Add the attribute extension to the extensions array
		extensions[count-1] = pkix.Extension{Id: TCertEncAttributes, Critical: false, Value: value}
	}

	// Append the TCertIndex to the extensions
	extensions = append(extensions, pkix.Extension{Id: TCertEncTCertIndex, Critical: true, Value: tidx})

	// Append the encrypted EnrollmentID to the extensions
	extensions = append(extensions, pkix.Extension{Id: TCertEncEnrollmentID, Critical: false, Value: encEnrollmentID})

	// Append the attributes header if there was attributes to include in the TCert
	if len(attributeSet) > 0 {
		extensions = append(extensions, pkix.Extension{Id: TCertAttributesHeaders, Critical: false, Value: buildAttributesHeader(attributesHeader)})
	}

	return extensions, ks, nil
}

func buildAttributesHeader(attributesHeader map[string]int) []byte {
	var headerString string
	for k, v := range attributesHeader {
		headerString = headerString + k + "->" + strconv.Itoa(v) + "#"
	}
	return []byte(headerString)
}
