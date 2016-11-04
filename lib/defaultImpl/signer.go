package defaultImpl

import (
	"errors"

	"github.com/hyperledger/fabric-cop/idp"
)

func newSigner(key []byte, cert []byte) Signer {
	return Signer{newVerifier(cert), key}
}

// Signer implements idp.Signer interface
type Signer struct {
	Verifier
	Key []byte `json:"key"`
}

// Sign the message
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	return nil, errors.New("NotImplemented")
}

// SignOpts the message with options
func (s *Signer) SignOpts(msg []byte, opts idp.SignatureOpts) ([]byte, error) {
	return nil, errors.New("NotImplemented")
}

// NewAttributeProof creates a proof for an attribute
func (s *Signer) NewAttributeProof(spec *idp.AttributeProofSpec) (proof []byte, err error) {
	return nil, errors.New("NotImplemented")
}

// TODO:
func (s *Signer) getMyKey() []byte {
	return s.Key
}
