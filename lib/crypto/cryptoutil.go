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
	"crypto"
	"errors"
	"fmt"
	"io"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"math/big"

	"github.com/cloudflare/cfssl/log"
)

const (
	// AESKeyLength is the default AES key length
	AESKeyLength = 32
)

var (
	//RootPreKeySize is the default value of root key
	RootPreKeySize = 48
)

//GenNumber generates random numbers of type *big.Int with fixed length
func GenNumber(numlen *big.Int) *big.Int {
	lowerBound := new(big.Int).Exp(big.NewInt(10), new(big.Int).Sub(numlen, big.NewInt(1)), nil)
	upperBound := new(big.Int).Exp(big.NewInt(10), numlen, nil)
	randomNum, _ := rand.Int(rand.Reader, upperBound)
	val := new(big.Int).Add(randomNum, lowerBound)
	valMod := new(big.Int).Mod(val, upperBound)

	if valMod.Cmp(lowerBound) == -1 {
		newval := new(big.Int).Add(valMod, lowerBound)
		return newval
	}
	return valMod
}

//GetCAKeyAndCert function reads CA key and Cert file from resource
//and converts it to privateKey and Certicate Object
func GetCAKeyAndCert() (interface{}, *x509.Certificate, error) {

	jsonString := ConvertJSONFileToJSONString("cacertlocation.json")

	privateKeyFile, error := ReadJSONAsMapString(jsonString, "CAKeyFile")

	if error != nil {
		log.Error("Cannot retrieve Private Key. The CA Key/Cert json file is malformed")
		return nil, nil, errors.New("Cannot retrieve Private Key. The CA Key/Cert json file is malformed")
	}
	privateKeyBuff, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		log.Error("Cannot get Private Key")
		return nil, nil, errors.New("Private Key cannot be obtained from file system")
	}
	caPrivateKey, err := GetPrivateKey(privateKeyBuff)
	if err != nil {
		log.Error("CA Private Key Object cannot be generated")
		return nil, nil, errors.New("CA Certificate Private Key Object cannot be generated")
	}

	certificateFile, caerror := ReadJSONAsMapString(jsonString, "CACertificate")
	if caerror != nil {
		log.Error("Cannot retrieve Certificate. The CA Key/Cert json file is malformed")
		return nil, nil, errors.New("Cannot retrieve Certificate. The CA Key/Cert json file is malformed")
	}

	certificateBuff, err := ioutil.ReadFile(certificateFile)
	if err != nil {
		log.Error("Cannot get CA certificate")
		return nil, nil, errors.New("Cannot get certificate file")
	}
	certificate, err := GetCertificate(certificateBuff)
	if err != nil {
		log.Fatal("CA Certificate cannot be generated")
		return nil, nil, errors.New("CA Certificate cannot be generated")
	}

	return caPrivateKey, certificate, nil

}

//GetCertificate returns interface containing *rsa.PublicKey or ecdsa.PublicKey
func GetCertificate(certificate []byte) (*x509.Certificate, error) {

	var certificates []*x509.Certificate
	var isvalidCert bool
	var err error

	block, _ := pem.Decode(certificate)
	if block == nil {
		certificates, err = x509.ParseCertificates(certificate)
		if err != nil {
			log.Error("Certificate Parse failed")
			return nil, errors.New("DER Certificate Parse failed")
		} //else {
		isvalidCert = ValidateCert(certificates[0])
		if !isvalidCert {
			log.Error("Certificate expired")
			return nil, errors.New("Certificate expired")
		}
		//}
	} else {
		certificates, err = x509.ParseCertificates(block.Bytes)
		if err != nil {
			log.Fatal("PEM Certificatre Parse failed")
			return nil, errors.New("PEM  Certificate Parse failed")
		} //else {
		isvalidCert = ValidateCert(certificates[0])
		if !isvalidCert {
			log.Error("Certificate expired")
			return nil, errors.New("Certificate expired")
		}
		//}
	}
	return certificates[0], nil

}

//GetCertificateSerialNumber returns serial number for Certificate byte
//return -1 , if there is problem with the cert
func GetCertificateSerialNumber(certificatebyte []byte) (*big.Int, error) {
	certificate, error := GetCertificate(certificatebyte)
	if error != nil {
		log.Error("Not a valid Certificate")
		return big.NewInt(-1), error
	}
	return certificate.SerialNumber, nil
}

//GetCertificateAKI returns the authority key idenitifier for Certificate byte
//return -1 , if there is problem with the cert
func GetCertificateAKI(certificatebyte []byte) ([]byte, error) {
	certificate, error := GetCertificate(certificatebyte)
	if error != nil {
		log.Error("Not a valid Certificate")
		return nil, error
	}
	return certificate.AuthorityKeyId, nil
}

//GetPrivateKey returns ecdsa.PrivateKey or rsa.privateKey object for the private Key Bytes
//Der Format is not supported
func GetPrivateKey(privateKeyBuff []byte) (interface{}, error) {

	var err error
	var privateKey interface{}

	block, _ := pem.Decode(privateKeyBuff)
	if block == nil {
		privateKey, err = parsePrivateKey(privateKeyBuff)
		if err != nil {
			log.Error("Private Key in DER format is not generated")
			return nil, errors.New("Private Key in DER format is not generated")
		}
		//return nil, errors.New("Failed decoding PEM Block")
	} else {
		privateKey, err = parsePrivateKey(block.Bytes)
		if err != nil {
			log.Error("Private Key in PEM format is not generated")
			return nil, errors.New("Private Key in PEM format is not generated")
		}
	}

	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		return privateKey, nil
	case *ecdsa.PrivateKey:
		return privateKey, nil
	default:
		return nil, errors.New("Key is not of correct type")
	}

}

// parsePrivateKey parses private key
func parsePrivateKey(der []byte) (interface{}, error) {

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {

		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("crypto/tls: failed to parse private key")
}

//VerifyMessage Gets Public Key from Certificate
//Certificate can be in PEM or DER Format
//It verifies both RSA and EC signatures**/
func VerifyMessage(jsonString string, signatureString string) bool {
	//Get Cert from the JSON
	ecert, error := ReadJSONAsMapString(signatureString, "Certificate")
	if error != nil {
		return false
	}

	raw, decodingErr := base64.StdEncoding.DecodeString(ecert)
	if decodingErr != nil {
		log.Error("Error Decoding Certififcate")
		return false
	}

	certificate, err := GetCertificate(raw)
	if err != nil {
		log.Error("Certificate Object cannot be retrieved")
		return false
	}

	pub := certificate.PublicKey

	if pub == nil {
		log.Fatal("Public Key is nil")
		return false
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		log.Debug("pub is of type RSA:", pub)
		return (VerifyRSAMessageImpl(jsonString, signatureString, pub))

	case *ecdsa.PublicKey:
		log.Debug("pub is of type ECDSA:", pub)

		return (VerifyECMessageImpl(jsonString, signatureString, pub))
	default:
		log.Fatal("unknown type of public key")
	}
	return false
}

// RSASign Signs Message as per RSA Algo
// returns RSA bigint String Signature
// ShaAlgo is hard coded right now to SHA384. Will implement dynamic algo**/
func RSASign(message []byte, shaAlgo string, rsaPrivateKey *rsa.PrivateKey) (string, error) {
	rng := rand.Reader
	//hashed := sha256.Sum256(message
	var hashed []byte
	var signature []byte
	var err error

	switch shaAlgo {
	case "SHA2_256":
		//Not yet implemented
	case "SHA2_384":

		hash := sha512.New384()
		hash.Write(message)
		hashed = hash.Sum(nil)
		signature, err = rsa.SignPKCS1v15(rng, rsaPrivateKey, crypto.SHA384, hashed[:])
	default:

		return "", errors.New("Correct Hash Algorithm is not being passed in the call")
	}

	if err != nil {
		log.Fatal("Error om signing: ", err)
		return "", errors.New("Error in RSA signing")
	}
	sig := base64.StdEncoding.EncodeToString(signature)
	return sig, nil

}

// RSAVerifySig Verifies RSA Signature
// return boolean
func RSAVerifySig(publicKey *rsa.PublicKey, hashAlgo string, signature string, message []byte) bool {
	sig, _ := base64.StdEncoding.DecodeString(signature)

	switch hashAlgo {
	case "SHA2_256":
		//Not yet implemented
	case "SHA2_384":

		hash := sha512.New384()
		hash.Write(message)
		hashed := hash.Sum(nil)
		err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA384, hashed[:], sig)
		if err != nil {
			return false
		}
	default:

		return false
	}

	return true
}

//VerifyRSAMessageImpl implements the RSA signature verification
func VerifyRSAMessageImpl(jsonString string, signatureString string, publicKey *rsa.PublicKey) bool {
	signature, error := ReadJSONAsMapString(signatureString, "RSASignature")
	if error != nil {
		log.Error("Malformed Signature String")
		return false
	}
	hashAlgo, hashError := ReadJSONAsMapString(signatureString, "HashAlgo")
	if hashError != nil {
		log.Error("Malformed Signature String")
		return false
	}

	return RSAVerifySig(publicKey /*"SHA384" */, hashAlgo, signature, []byte(jsonString))
}

//VerifyECMessageImpl implements the Elliptic Curve signature verification
func VerifyECMessageImpl(JSONString string, signatureString string, pub *ecdsa.PublicKey) bool {

	R, rerror := ReadJSONAsMapString(signatureString, "ECSignature.R")
	if rerror != nil {
		return false
	}
	S, serror := ReadJSONAsMapString(signatureString, "ECSignature.S")
	if serror != nil {
		return false
	}

	r, s := big.NewInt(0), big.NewInt(0)
	r.SetString(R, 10)
	s.SetString(S, 10)

	hash := sha256.New()
	hash.Write([]byte(JSONString))
	hashed := hash.Sum(nil)

	if ecdsa.Verify(pub, hashed, r, s) == false {

		return false
	}
	return true
}

//ECDSASignDirect signs the message msg and returns R,S using ECDSA
func ECDSASignDirect(signKey interface{}, msg []byte) (*big.Int, *big.Int, error) {
	temp := signKey.(*ecdsa.PrivateKey)
	//hash := sha512.New384()
	hash := sha256.New()
	hash.Write(msg)
	h := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, temp, h)
	if err != nil {
		return nil, nil, err
	}
	return r, s, nil
}

//SignECMessage generates a certificate and privKey and returns a signedJSON string containing the R and S value.
func SignECMessage(JSONString string, signatureJSON string, signKey interface{}, certificateBuff []byte) string {

	raw := []byte(JSONString)
	r, s, err := ECDSASignDirect(signKey.(*ecdsa.PrivateKey), raw)
	if err != nil {
		log.Fatal("Error in SignECMessage ECDSASignDirect fails to sign:", err)
	}
	var R = r.String()
	var S = s.String()

	encodedCert := base64.StdEncoding.EncodeToString(certificateBuff)

	valueMap := make(map[string]string)
	valueMap["ECSignature.R"] = R
	valueMap["ECSignature.S"] = S
	valueMap["Certificate"] = encodedCert
	var signedJSON = WriteJSONToString(signatureJSON, valueMap)

	return signedJSON
}

//RSASignJSON  Signs JSon string
//jsonString : JSonString to be signed
//signatureJson : json string containing signature and ECert
//certificate : in based64 encoding
//returns JSON String with updated signature */
func RSASignJSON(jsonString string, hashalgo string, signatureJSON string, rsaPrivateKey *rsa.PrivateKey, cert string) (string, error) {
	message := []byte(jsonString)

	signature, error := RSASign(message, hashalgo, rsaPrivateKey)
	if error != nil {
		log.Error("RSA Signature Problem", error)
		return "", errors.New("RSA Signature Problem")
	}
	valueMap := make(map[string]string)
	valueMap["RSASignature"] = signature
	valueMap["Certificate"] = cert
	valueMap["HashAlgo"] = hashalgo //This line added
	var signedJSON = WriteJSONToString(signatureJSON, valueMap)

	return signedJSON, nil
}

//ValidateCert checks for expiry in the certificate cert
//Does not check for revocation
func ValidateCert(cert *x509.Certificate) bool {
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	currentTime := time.Now()
	diffFromExpiry := notAfter.Sub(currentTime)
	diffFromStart := currentTime.Sub(notBefore)
	return ((diffFromExpiry > 0) && (diffFromStart > 0))
}

// CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	return CBCEncrypt(key, PKCS7Padding(src))
}

// CBCEncrypt encrypts using CBC mode
func CBCEncrypt(key, s []byte) ([]byte, error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(s))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext, nil
}

// PKCS7Padding pads as prescribed by the PKCS7 standard
func PKCS7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	pt, err := CBCDecrypt(key, src)
	if err != nil {

		return nil, err
	}

	original, err := PKCS7UnPadding(pt)
	if err != nil {

		return nil, err
	}

	return original, nil
}

// CBCDecrypt decrypts using CBC mode
func CBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {

		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < aes.BlockSize {

		return nil, errors.New("ciphertext too short")
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {

		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(src, src)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	return src, nil
}

// PKCS7UnPadding unpads as prescribed by the PKCS7 standard
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return src[:(length - unpadding)], nil
}

//CreateRootPreKey method generates root key
func CreateRootPreKey() string {
	var cooked string
	key := make([]byte, RootPreKeySize)
	rand.Reader.Read(key)
	cooked = base64.StdEncoding.EncodeToString(key)
	return cooked
}

// GenerateIntUUID returns a UUID based on RFC 4122 returning a big.Int
func GenerateIntUUID() *big.Int {
	uuid := GenerateBytesUUID()
	z := big.NewInt(0)
	return z.SetBytes(uuid)
}

// GenerateBytesUUID returns a UUID based on RFC 4122 returning the generated bytes
func GenerateBytesUUID() []byte {
	uuid := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, uuid)
	if err != nil {
		panic(fmt.Sprintf("Error generating UUID: %s", err))
	}

	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80

	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40

	return uuid
}

//calulateHash calcultes hash based on the hashAlgorithm passed
//ShA3 is not being tested
/*
func calculateHash(msgTohash []byte, hashAlgorithm string) ([]byte, error) {

	var hashed []byte

	switch hashAlgorithm {
	case "SHA2_256":
		hash := sha256.New()
		hash.Write(msgTohash)
		hashed = hash.Sum(nil)
	case "SHA2_384":
		hash := sha512.New384()
		hash.Write(msgTohash)
		hashed = hash.Sum(nil)

	default:
		return nil, errors.New("Correct Hash Algorithm is not being passed in the call")
	}

	return hashed, nil
}
*/
