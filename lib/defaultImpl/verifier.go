package defaultImpl

import (
	"errors"

	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

func newVerifier(cert []byte) Verifier {
	return Verifier{cert}
}

// Verifier implements the idp.Verifier interface
type Verifier struct {
	Cert []byte `json:"cert"`
}

// VerifySelf verifies myself
func (v *Verifier) VerifySelf() error {
	return errors.New("NotImplemented")
}

// Verify a signature over some message
func (v *Verifier) Verify(msg []byte, sig []byte) error {
	return errors.New("NotImplemented")
}

// VerifyOpts verifies a signature over some message with options
func (v *Verifier) VerifyOpts(msg []byte, sig []byte, opts idp.SignatureOpts) error {
	return errors.New("NotImplemented")
}

// VerifyAttributes verifies attributes given proofs
func (v *Verifier) VerifyAttributes(proof [][]byte, spec *idp.AttributeProofSpec) error {
	return errors.New("NotImplemented")
}

// Serialize a verifier
func (v *Verifier) Serialize() ([]byte, error) {
	return util.Marshal(v, "Verifier")
}

func (v *Verifier) getMyCert() []byte {
	return v.Cert
}
