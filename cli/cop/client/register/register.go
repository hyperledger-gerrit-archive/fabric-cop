package register

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	cutil "github.com/hyperledger/fabric-cop/cli/cop/client"
	"github.com/hyperledger/fabric-cop/idp"
	lib "github.com/hyperledger/fabric-cop/lib/defaultImpl"

	"github.com/hyperledger/fabric-cop/util"
)

var usageText = `cop client register -- Register an ID with COP server and return an enrollment secret

Usage of client register command:
    Register a client with COP server:
        cop client register REGISTER-REQUEST-FILE COP-SERVER-ADDR

Arguments:
        RRJSON:             File contains registration info
        COP-SERVER-ADDR:    COP server address
Flags:
`

var flags = []string{}

func myMain(args []string, c cli.Config) error {

	regFile, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	buf, err := util.ReadFile(regFile)
	if err != nil {
		return err
	}

	callerID, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}
	_ = callerID

	regReq := new(idp.RegistrationRequest)
	err = json.Unmarshal(buf, regReq)
	if err != nil {
		return err
	}
	home := util.GetDefaultHomeDir()
	identity, err := util.ReadFile(home + "/client.json")
	if err != nil {
		log.Error(err)
		return err
	}
	id := new(lib.Identity)
	err = util.Unmarshal(identity, id, "idp.Identity")
	if err != nil {
		log.Error(err)
		return err
	}

	copServer, _, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	client, err := cutil.NewClient(copServer)
	if err != nil {
		return err
	}
	regReq.Registrar = id
	resp, err := client.Register(regReq)
	if err != nil {
		return err
	}

	secretBytes, err := base64.StdEncoding.DecodeString(resp.Secret)
	if err != nil {
		cop.WrapError(err, cop.EnrollingUserError, "Failed to decode string to bytes")
	}

	fmt.Printf("One time Password: %s\n", string(secretBytes))

	return nil
}

// Command assembles the definition of Command 'enroll'
var Command = &cli.Command{UsageText: usageText, Flags: flags, Main: myMain}
