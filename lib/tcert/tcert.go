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
	"encoding/json"

	"math/big"
	"strconv"

	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/log"

	crypto "github.com/hyperledger/fabric-cop/lib/crypto"
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

/** Each member will have 1 Pre Key **/
/** Will look into persistence later */
func getPreKFrom(resourceType string) string {

	key := make([]byte, 49)
	rand.Reader.Read(key)
	var cooked = base64.StdEncoding.EncodeToString(key)
	return cooked
}

// GetCertificateSet requests the creation of a new transaction certificate set by the TCA.
/**
*  @jsonString : JSON containg request
*  @signatureString : JSON String containing Signature and Certificate
 */
func GetCertificateSet(jsonString string, signatureString string) (string, error) {
	//Trace.Println("gRPC TCAP:CreateCertificateSet")

	//Need to add Certificate value also
	if crypto.VerifyMessage(jsonString, signatureString) == false {
		return "", errors.New("Signature Validation on TCertRequest failed")
	}

	// Generate nonce for TCertIndex
	nonce := make([]byte, 16) // 8 bytes rand, 8 bytes timestamp
	rand.Reader.Read(nonce[:8])

	ecert, error := crypto.ReadJSONAsMapString(signatureString, "Certificate")
	if error != nil {
		log.Error("GetCertificateSet method : SignaureJSON is malformed")
		return "", error
	}

	raw, _ := base64.StdEncoding.DecodeString(ecert)
	//cert, err := x509.ParseCertificate(raw)
	cert, err := crypto.GetCertificate(raw)
	if err != nil {
		log.Error("Certificate object is nil")
		return "", err
	}

	pub := cert.PublicKey.(*ecdsa.PublicKey)
	//mac := hmac.New(sha512.New384(), tcap.tca.hmacKey)
	//Need to read HMAC key from persistent storage
	mac := hmac.New(sha512.New384, []byte(createHMACKey()))
	raw, _ = x509.MarshalPKIXPublicKey(pub)
	mac.Write(raw)
	kdfKey := mac.Sum(nil)

	numString, error := crypto.ReadJSONAsMapString(jsonString, "TCertBatchRequest.Num")
	if error != nil {
		return "", error
	}
	num, _ := strconv.Atoi(numString)

	if num == 0 {
		num = 1
	}

	/**  Need to work on from here **/
	// the batch of TCerts
	var set []TCert

	for i := 0; i < num; i++ {
		tcertid := crypto.GenerateIntUUID()

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
		encryptedTidx, encryptErr := crypto.CBCPKCS7Encrypt(extKey, tidx)
		if encryptErr != nil {
			return "", err
		}

		// TODO: We are storing each K used on the TCert in the ks array (the second return value of this call), but not returning it to the user.
		// We need to design a structure to return each TCert and the associated Ks.
		extensions, ks, extensionErr := generateExtensions(tcertid, encryptedTidx, cert, jsonString)

		if extensionErr != nil {
			log.Error("Certificate Extenstion cannot be generated")
		}

		spec, specError := crypto.ParseCertificateRequest(jsonString, tcertid, &txPub, x509.KeyUsageDigitalSignature, extensions)

		if specError != nil {
			return "", specError
		}
		//spec := NewDefaultPeriodCertificateSpec(id, tcertid, &txPub, x509.KeyUsageDigitalSignature, extensions...)
		//Needs to persist kdf key and TimeStamp for each cert : Will look into it in next iteration
		//
		if raw, err = crypto.NewCertificateFromSpec(spec); err != nil {
			fmt.Println("problem", err)
			log.Error(err)
			return "", err
		}

		//set = append(set, &pb.TCert{raw, ks})
		//Set Certificates in BASE64 encoded format

		set = append(set, TCert{base64.StdEncoding.EncodeToString(raw), ks})
	}

	//Id is hardcoded right now. Need to look into Timestamp part as well. Removed timestamp for the time being
	tcertResponse := CreateSetResp{&CertSet{"123", kdfKey, set}}
	tcertResponseJSONByte, err := json.Marshal(tcertResponse)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return string(tcertResponseJSONByte), nil
}

//func (tcap *TCAP) generateExtensions(tcertid *big.Int, tidx []byte, enrollmentCert *x509.Certificate, attrs []*pb.ACAAttribute) ([]pkix.Extension, []byte, error) {

// Generate encrypted extensions to be included into the TCert (TCertIndex, EnrollmentID and attributes).
func generateExtensions(tcertid *big.Int, tidx []byte, enrollmentCert *x509.Certificate, jsonString string) ([]pkix.Extension, map[string][]byte, error) {
	// For each TCert we need to store and retrieve to the user the list of Ks used to encrypt the EnrollmentID and the attributes.
	//read attributes from JSON string
	attributes := crypto.GetAttributes(jsonString)
	ks := make(map[string][]byte)
	extensions := make([]pkix.Extension, len(attributes))

	//get Pre-Key from json string
	// Compute preK_1 to encrypt attributes and enrollment ID
	/*
		preK1, err := tcap.tca.getPreKFrom(enrollmentCert)
		if err != nil {
			return nil, nil, err
		}
	*/
	//Get Pre Key from json string
	//We need to get it from DB , so no error handling for the time being
	preK1, error := crypto.ReadJSONAsMapString(jsonString, "TCertBatchRequest.RootPreKey")
	if error != nil {
		log.Error("The Request JSON string is malformed")
	}

	//mac := hmac.New(primitives.GetDefaultHash(), preK1)
	mac := hmac.New(sha512.New384, []byte(preK1))
	mac.Write(tcertid.Bytes())
	preK0 := mac.Sum(nil)

	// Compute encrypted EnrollmentID
	mac = hmac.New(sha512.New384, preK0)
	mac.Write([]byte("enrollmentID"))
	enrollmentIDKey := mac.Sum(nil)[:32]

	enrollmentID := []byte(enrollmentCert.Subject.CommonName)
	enrollmentID = append(enrollmentID, Padding...)

	encEnrollmentID, err := crypto.CBCPKCS7Encrypt(enrollmentIDKey, enrollmentID)
	if err != nil {
		return nil, nil, err
	}

	// save k used to encrypt EnrollmentID
	ks["enrollmentId"] = enrollmentIDKey

	attributeIdentifierIndex := 9
	count := 0
	attributesHeader := make(map[string]int)
	// Encrypt and append attributes to the extensions slice
	for AttributeName, AttributeValue := range attributes {
		count++
		value := []byte(AttributeValue)

		//Save the position of the attribute extension on the header.
		attributesHeader[AttributeName] = count

		if crypto.IsAttributeEncryptionEnabled(jsonString) {
			mac = hmac.New(sha512.New384, preK0)
			mac.Write([]byte(AttributeName))
			attributeKey := mac.Sum(nil)[:32]

			value = append(value, Padding...)
			value, err = crypto.CBCPKCS7Encrypt(attributeKey, value)
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
	if len(attributes) > 0 {
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
