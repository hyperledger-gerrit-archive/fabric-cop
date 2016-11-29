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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/log"
)

//CertificateSpec defines structure for Certificate template
type CertificateSpec struct {
	commonName       string
	serialNumber     *big.Int
	pub              interface{}
	usage            x509.KeyUsage
	NotBefore        time.Time
	NotAfter         time.Time
	ext              *[]pkix.Extension
	country          string
	State            string
	locality         string
	Organization     string
	OrganizationUnit string
}

//NewCertificateFromSpec generates cerficate based on template passed
func NewCertificateFromSpec(spec *CertificateSpec) ([]byte, error) {

	var isCA = false

	tmpl := x509.Certificate{
		SerialNumber: spec.GetSerialNumber(),
		Subject: pkix.Name{
			CommonName:         spec.GetCommonName(),
			Organization:       []string{spec.GetOrganization()},
			OrganizationalUnit: []string{spec.GetOrganizationalUnit()},
			Province:           []string{spec.GetState()},
			Country:            []string{spec.GetCountry()},
			Locality:           []string{spec.GetLocality()},
		},
		NotBefore: spec.GetNotBefore(),
		NotAfter:  spec.GetNotAfter(),

		SubjectKeyId:       *spec.GetSubjectKeyID(),
		SignatureAlgorithm: spec.GetSignatureAlgorithm(),
		KeyUsage:           spec.GetUsage(),

		BasicConstraintsValid: true,
		IsCA: isCA,
	}

	if len(*spec.GetExtensions()) > 0 {
		tmpl.Extensions = *spec.GetExtensions()
		tmpl.ExtraExtensions = *spec.GetExtensions()
	}

	pub := spec.GetPublicKey()

	privateKey, certificate, err := GetCAKeyAndCert()
	if err != nil {
		log.Error("Problem in getting CA certificat and Key object generation")
		return nil, err
	}
	raw, err := x509.CreateCertificate(rand.Reader, &tmpl, certificate, pub, privateKey)
	log.Debug("Certificate Created")
	if err != nil {
		log.Error("Certificate Generation failed")
		return nil, err
	}

	pem := ConvertDERToPEM(raw, "CERTIFICATE")
	return pem, nil
}

// GetCommonName returns the spec's Common Name field/value
//
func (spec *CertificateSpec) GetCommonName() string {
	return spec.commonName
}

// GetSerialNumber returns the spec's Serial Number field/value
//
func (spec *CertificateSpec) GetSerialNumber() *big.Int {
	return spec.serialNumber
}

// GetPublicKey returns the spec's Public Key field/value
//
func (spec *CertificateSpec) GetPublicKey() interface{} {
	return spec.pub
}

// GetUsage returns the spec's usage (which is the x509.KeyUsage) field/value
//
func (spec *CertificateSpec) GetUsage() x509.KeyUsage {
	return spec.usage
}

// GetNotBefore returns the spec NotBefore (time.Time) field/value
//
func (spec *CertificateSpec) GetNotBefore() time.Time {
	return spec.NotBefore
}

// GetNotAfter returns the spec NotAfter (time.Time) field/value
//
func (spec *CertificateSpec) GetNotAfter() time.Time {
	return spec.NotAfter
}

// GetOrganization returns the spec's Organization field/value
//
func (spec *CertificateSpec) GetOrganization() string {
	return spec.Organization
}

// GetCountry returns the spec's Country field/value
//
func (spec *CertificateSpec) GetCountry() string {
	return spec.country
}

// GetSubjectKeyID returns the spec's subject KeyID
//
func (spec *CertificateSpec) GetSubjectKeyID() *[]byte {
	return &[]byte{1, 2, 3, 4}
}

// GetSignatureAlgorithm returns the X509.SignatureAlgorithm field/value
//
func (spec *CertificateSpec) GetSignatureAlgorithm() x509.SignatureAlgorithm {
	return x509.ECDSAWithSHA384
}

// GetExtensions returns the sepc's extensions
//
func (spec *CertificateSpec) GetExtensions() *[]pkix.Extension {
	return spec.ext
}

//GetLocality returs subject's locality
func (spec *CertificateSpec) GetLocality() string {
	return spec.locality
}

//GetOrganizationalUnit returns subject's OrganizationalUNIT
func (spec *CertificateSpec) GetOrganizationalUnit() string {
	return spec.OrganizationUnit
}

//GetState returns subejct's state
func (spec *CertificateSpec) GetState() string {
	return spec.State
}
