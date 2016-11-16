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

package server

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/serve"
	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
)

// Usage text of 'cfssl serve'
var serverUsageText = `cop server start -- start the COP server

Usage:
        cop server start [-address address] [-ca cert] [-ca-bundle bundle] \
                         [-ca-key key] [-int-bundle bundle] [-int-dir dir] [-port port] \
                         [-metadata file] [-remote remote_host] [-config config] \
                         [-responder cert] [-responder-key key] [-tls-cert cert] [-tls-key key] \
                         [-mutual-tls-ca ca] [-mutual-tls-cn regex] \
                         [-tls-remote-ca ca] [-mutual-tls-client-cert cert] [-mutual-tls-client-key key] \
                         [-db-config db-config]

Flags:
`

// Flags used by 'cfssl serve'
var serverFlags = []string{"address", "port", "ca", "ca-key", "ca-bundle", "int-bundle", "int-dir", "metadata",
	"remote", "config", "responder", "responder-key", "tls-key", "tls-cert", "mutual-tls-ca", "mutual-tls-cn",
	"tls-remote-ca", "mutual-tls-client-cert", "mutual-tls-client-key", "db-config"}

var (
	mutex = &sync.RWMutex{}
)

// Server ...
type Server struct {
}

// Command defines the command will start the server and registers endpoints
func Command() {
	// The server commands
	cmds := map[string]*cli.Command{
		"start": StartCommand,
	}
	// Set the authentication handler
	serve.SetWrapHandler(NewAuthWrapper)
	// Add the "register" route/endpoint
	serve.SetEndpoint("register", NewRegisterHandler)
	// Add the "enroll" route/endpoint
	serve.SetEndpoint("enroll", NewEnrollHandler)

	// If the CLI returns an error, exit with an appropriate status code.
	err := cli.Start(cmds)
	if err != nil {
		os.Exit(1)
	}
}

// CreateHome will create a home directory if it does not exist
func (s *Server) CreateHome() (string, error) {
	log.Debug("CreateHome")
	home := os.Getenv("COP_HOME")
	if home == "" {
		home = os.Getenv("HOME")
		if home != "" {
			home = home + "/.cop"
		}
	}
	if home == "" {
		home = "/var/hyperledger/production/.cop"
	}
	if _, err := os.Stat(home); err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(home, 0755)
			if err != nil {
				return "", err
			}
		}
	}

	return home, nil
}

func (s *Server) checkForDB(cfg *Config) (*sqlx.DB, error) {
	log.Debugf("Check if database exists: %s", cfg.DataSource)
	var err error
	var db *sqlx.DB

	switch cfg.DBdriver {
	case "sqlite3":
		db, err = s.SQLiteDB(cfg)
		// More cases to be added
	default:
		log.Error("Unsupported database driver")
		return nil, cop.NewError(cop.DatabaseError, "Unsupported database driver")
	}

	if err != nil {
		return nil, err
	}

	return db, nil
}

// SQLiteDB checks if sqlite database exists
func (s *Server) SQLiteDB(cfg *Config) (*sqlx.DB, error) {
	log.Debugf("Using sqlite database, connect to database in home (%s) directory", cfg.Home)
	dataSource := filepath.Join(cfg.Home, cfg.DataSource)
	cfg.DataSource = dataSource

	if dataSource != "" {
		// Check if database exists if not create it and bootstrap it based on the config file
		if _, err := os.Stat(dataSource); err != nil {
			if os.IsNotExist(err) {
				log.Debug("Database not found")
				_, err := util.CreateSQLiteDB(dataSource)
				if err != nil {
					return nil, err
				}

			}
		}
	}

	db, err := sqlx.Open("sqlite3", cfg.DataSource)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// BootstrapDB loads the database based on config file
func (s *Server) BootstrapDB(cfg *Config) error {
	log.Debug("Bootstrap DB")
	b := BootstrapDB()
	b.PopulateGroupsTable()
	b.PopulateUsersTable()

	return nil
}

// startMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle sign, bundle, and validate requests.
func startMain(args []string, c cli.Config) error {
	log.Debug("server.startMain")

	s := new(Server)
	home, err := s.CreateHome()
	if err != nil {
		return err
	}
	configInit(&c)
	cfg := CFG
	cfg.Home = home

	if cfg.DataSource == "" {
		msg := "No database specified, a database is needed to run cop server"
		log.Fatal(msg)
		return cop.NewError(cop.DatabaseError, msg)
	}

	db, err := s.checkForDB(cfg)
	if err != nil {
		log.Error("Failed to get database")
		return err
	}

	cfg.DB = db
	cfg.DBAccessor = NewDBAccessor()
	cfg.DBAccessor.SetDB(db)

	s.BootstrapDB(cfg)

	return serve.Command.Main(args, c)
}

// Start will start server - only used for test case execution
func Start(dir string) {
	log.Debug("Server starting")
	osArgs := os.Args
	cert := filepath.Join(dir, "ec.pem")
	key := filepath.Join(dir, "ec-key.pem")
	config := filepath.Join(dir, "testconfig.json")
	os.Args = []string{"server", "start", "-ca", cert, "-ca-key", key, "-config", config}
	Command()
	os.Args = osArgs
}

// StartCommand assembles the definition of Command 'serve'
var StartCommand = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: startMain}
