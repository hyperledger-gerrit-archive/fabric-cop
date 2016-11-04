package server

//
// import (
// 	"fmt"
// 	"os"
// 	"testing"
// 	"time"
//
// 	main "github.com/hyperledger/fabric-cop/cli/cop"
// 	cutil "github.com/hyperledger/fabric-cop/cli/cop/client"
// 	"github.com/hyperledger/fabric-cop/idp"
// 	"github.com/jmoiron/sqlx"
// )
//
// const (
// 	enrollPath = "/tmp/enrollTest"
// )
//
// const (
// 	CERT  string = "../../../testdata/ec.pem"
// 	KEY   string = "../../../testdata/ec-key.pem"
// 	CFG   string = "../../../testdata/cop.json"
// 	DBCFG string = "../../../testdata/enrollTest.json"
// 	CSR   string = "../../../testdata/csr.json"
// )
//
// var serverStarted bool
// var serverExitCode = 0
//
// func prepEnrollTest() *sqlx.DB {
// 	if _, err := os.Stat(enrollPath); err != nil {
// 		if os.IsNotExist(err) {
// 			os.MkdirAll(enrollPath, 0755)
// 		}
// 	} else {
// 		os.RemoveAll(enrollPath)
// 		os.MkdirAll(enrollPath, 0755)
// 	}
// 	// os.Setenv("COP_DEBUG", "true")
// 	// os.Setenv("COP_HOME", enrollPath)
// 	// // cfg := new(cli.Config)
// 	// var cfg cli.Config
// 	// cfg.CAFile = CERT
// 	// cfg.CAKeyFile = KEY
// 	// cfg.ConfigFile = CFG
// 	// cfg.DBConfigFile = DBCFG
// 	// cfg.Address = "127.0.0.1"
// 	// cfg.Port = 8888
// 	//
// 	// var args []string
// 	// go startMain(args, cfg)
// 	// time.Sleep(5 * time.Second)
// 	// config.Init(cfg)
//
// 	// enrollCFG := config.CFG
// 	// db, _ := util.CreateTables(enrollCFG)
// 	// // db, _ := util.GetDB("sqlite3", "tmp/hyperledger/enrollTest/enroll.db")
// 	// bootstrapGroups(db)
// 	// bootstrapRegistrar(Registrar)
// 	//
// 	// startServer()
// 	return nil
//
// }
//
// func startServer() int {
// 	if !serverStarted {
// 		serverStarted = true
// 		fmt.Println("starting COP server ...")
// 		go runServer()
// 		time.Sleep(3 * time.Second)
// 		fmt.Println("COP server started")
// 	} else {
// 		fmt.Println("COP server already started")
// 	}
// 	return serverExitCode
// }
//
// func runServer() {
// 	os.Setenv("COP_DEBUG", "true")
// 	serverExitCode = main.COPMain([]string{"cop", "server", "start", "-ca", CERT, "-ca-key", KEY, "-config", CFG})
// }
//
// // func runServer() {
// // 	fmt.Println("runServer")
// // 	os.Setenv("COP_DEBUG", "true")
// // 	// args := []string{"ca", CERT, "ca-key", KEY, "config", CFG, "db-config", DBCFG, "loglevel=0"}
// // 	args := []string{}
// // 	var c cli.Config
// // 	c.CAFile = CERT
// // 	c.CAKeyFile = KEY
// // 	c.ConfigFile = CFG
// // 	c.DBConfigFile = DBCFG
// // 	err := serve.Command.Main(args, c)
// // 	if err != nil {
// // 		fmt.Println("err: ", err)
// // 	}
// // 	// serverExitCode = COPMain([]string{"cop", "server", "start", "-ca", CERT, "-ca-key", KEY, "-config", CFG})
// // }
//
// // func testEnrollUser(db *sqlx.DB, t *testing.T) {
// // 	tok, err := registerUser(Registrar, &testEnroll)
// // 	if err != nil {
// // 		t.Errorf("Failed to register user: %s, err: %s", testEnroll.User, err)
// // 	}
// //
// // 	// csr, err := ioutil.ReadFile("../../testdata/csr.json")
// // 	if err != nil {
// // 		t.Error(err)
// // 	}
// //
// // 	req := &cop.EnrollRequest{
// // 		User:  testEnroll.User,
// // 		Token: []byte(tok),
// // 	}
//
// // client := NewClient()
// // client.SetServerAddr("http://localhost:8888")
// // client.Enroll(req, "../../testdata/csr.json")
//
// // enroll := NewEnrollUser()
// // _, err = enroll.Enroll(testEnroll.User, []byte(tok), csrPEM, "http://localhost:8888")
// // if err != nil {
// // 	t.Error("Failed to enroll User, err: ", err)
// // }
//
// // }
//
// // func TestAllEnroll(t *testing.T) {
// // 	prepEnrollTest()
// //
// // 	testEnrollBootstrapUser(t)
// //
// // 	// testEnrollUser(db, t)
// // }
//
// func testEnrollBootstrapUser(t *testing.T) {
//
// 	client, err := cutil.NewClient("http://127.0.0.1:8888")
// 	if err != nil {
// 		t.Error("Failed to create client")
// 	}
//
// 	req := &idp.EnrollmentRequest{
// 		Name:   Registrar.User,
// 		Secret: string(Registrar.Pass),
// 	}
//
// 	_, err = client.Enroll(req)
// 	if err != nil {
// 		t.Log("Error: ", err)
// 		t.Error("Failed to enroll")
// 	}
// }
//
// // func testRegisterUser(t *testing.T) {
// // 	_, err := registerUser(Registrar, &testUser)
// // 	if err != nil {
// // 		t.Fatal(err.Error())
// // 	}
// // }
