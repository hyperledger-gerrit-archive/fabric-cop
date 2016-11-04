package server

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"path/filepath"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/cop/config"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
)

// registerHandler for register requests
type enrollHandler struct {
}

// NewEnrollHandler is constructor for register handler
func NewEnrollHandler() (h http.Handler, err error) {
	// NewHandler is constructor for register handler
	return &api.HTTPHandler{
		Handler: &enrollHandler{},
		Methods: []string{"POST"},
	}, nil
}

// Handle a register request
func (h *enrollHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("enroll request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	user, token, ok := r.BasicAuth()
	if !ok {
		log.Error("No authorization header set")
		return cop.NewError(cop.EnrollingUserError, "No authorization header set")
	}

	enroll := NewEnrollUser()
	cert, err := enroll.Enroll(user, []byte(token), body)
	if err != nil {
		return err
	}

	return api.SendResponse(w, cert)
}

type Enroll struct {
	DB         *sqlx.DB
	DbAccessor *Accessor
	cfg        *config.Config
}

func NewEnrollUser() *Enroll {
	e := new(Enroll)
	e.cfg = config.CFG
	home := e.cfg.Home
	dataSource := filepath.Join(home, e.cfg.DataSource)
	e.DB, _ = util.GetDB(e.cfg.DBdriver, dataSource)
	e.DbAccessor = NewDBAccessor()
	e.DbAccessor.SetDB(e.DB)
	return e
}

func (e *Enroll) Enroll(id string, token []byte, csrPEM []byte) ([]byte, cop.Error) {
	log.Debugf("Received request to enroll user with id: %s\n", id)
	mutex.Lock()
	defer mutex.Unlock()

	user, err := e.DbAccessor.GetUser(id)
	if err != nil {
		log.Error("User not registered")
		return nil, cop.WrapError(err, cop.EnrollingUserError, "User not registered")
	}

	if !bytes.Equal(token, []byte(user.Token)) {
		log.Error("Identity or token does not match")
		return nil, cop.NewError(cop.EnrollingUserError, "Identity or token does not match")
	}

	if user.State == 0 {
		cert, signErr := e.signKey(csrPEM)
		if signErr != nil {
			log.Error("Failed to sign CSR")
			return nil, signErr
		}

		ioutil.WriteFile("/tmp/cert2.pem", cert, 0755)
		tok := util.RandomString(12)

		updateState := cop.UserRecord{
			ID:       user.ID,
			Token:    tok,
			Metadata: user.Metadata,
			State:    1,
		}

		err = e.DbAccessor.UpdateUser(updateState)
		if err != nil {
			return nil, cop.WrapError(err, cop.EnrollingUserError, "Failed to updates user state")
		}

		return cert, nil
	}
	return nil, cop.NewError(cop.EnrollingUserError, "User was not enrolled")
}

// func (e *Enroll) signKey(csrPEM []byte, remoteHost string) ([]byte, cop.Error) {
func (e *Enroll) signKey(csrPEM []byte) ([]byte, cop.Error) {
	log.Debugf("signKey remoteHost=%s")
	var cfg cli.Config
	cfg.CAFile = e.cfg.CACert
	cfg.CAKeyFile = e.cfg.CAKey
	s, err := sign.SignerFromConfigAndDB(cfg, e.DB)
	if err != nil {
		log.Errorf("SignerFromConfig error: %s", err)
		return nil, cop.WrapError(err, cop.CFSSL, "failed in SignerFromConfig")
	}
	req := signer.SignRequest{
		// Hosts:   signer.SplitHosts(c.Hostname),
		Request: string(csrPEM),
		// Profile: c.Profile,
		// Label:   c.Label,
	}
	cert, err := s.Sign(req)
	if err != nil {
		log.Errorf("Sign error: %s", err)
		return nil, cop.WrapError(err, cop.CFSSL, "failed in Sign")
	}
	log.Debug("Sign success")
	return cert, nil

}
