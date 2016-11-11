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

type Server struct {
}

func ServerCommand() {
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

// ConfigureDB creates Database and Tables if they don't exist
// func (s *Server) ConfigureDB(dataSource string, cfg *Config) error {
// 	log.Debug("Configure DB")
// 	db, err := util.CreateDatabase(cfg.DBdriver, dataSource)
// 	if err != nil {
// 		return err
// 	}
//
// 	s.BootstrapDB(db, cfg)
//
// 	return nil
// }

// BootstrapDB loads the database based on config file
func (s *Server) BootstrapDB(db *sqlx.DB, cfg *Config) error {
	log.Debug("Bootstrap DB")
	b := BootstrapDB(db, cfg)
	b.PopulateGroupsTable()
	b.PopulateUsersTable()

	return nil
}

func (s *Server) checkForDB(cfg *Config) error {
	log.Debug("Check if database exists")
	var err error

	switch cfg.DBdriver {
	case "sqlite3":
		err = s.createSQLiteDB(cfg)
	case "postgres":
		err = s.createPostgres(cfg)
	}

	if err != nil {
		return err
	}

	return nil
}

func (s *Server) createSQLiteDB(cfg *Config) error {
	log.Debugf("Using sqlite database, looking for database in home (%s) directory", cfg.Home)
	dataSource := filepath.Join(cfg.Home, cfg.DataSource)

	if dataSource != "" {
		// Check if database exists if not create it and bootstrap it based on the config file
		if _, err := os.Stat(dataSource); err != nil {
			if os.IsNotExist(err) {
				log.Debug("Database not found")
				db, err := util.CreateSQLiteDB(dataSource)
				if err != nil {
					return err
				}
				s.BootstrapDB(db, cfg)
			}
		}
	}
	return nil
}

func (s *Server) createPostgres(cfg *Config) error {
	log.Debugf("Using postgres database, looking for database...")

	dbName := util.GetDBName(cfg.DataSource)
	log.Debug("Database Name: ", dbName)

	connStr := util.GetConnStr(cfg.DataSource)

	db, err := util.GetDB("postgres", connStr)
	if err != nil {
		return cop.WrapError(err, cop.DatabaseError, "Failed to connect to database")
	}

	// Check if database exists
	r, err := db.Exec("SELECT * FROM pg_catalog.pg_database where datname=$1", dbName)
	if err != nil {
		return cop.WrapError(err, cop.DatabaseError, "Failed to query 'pg_database' table")
	}

	found, _ := r.RowsAffected()
	if found == 0 {
		log.Debug("Database not found")
		db, err = util.CreatePostgresDB(cfg.DataSource, dbName, db)
		if err != nil {
			return err
		}
		s.BootstrapDB(db, cfg)
	}

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

	err = s.checkForDB(cfg)
	if err != nil {
		log.Error("Failed to create database")
		return err
	}

	return serve.Command.Main(args, c)
}

func Start(dir string) {
	log.Error("Server starting")

	osArgs := os.Args
	cert := filepath.Join(dir, "ec.pem")
	key := filepath.Join(dir, "ec-key.pem")
	config := filepath.Join(dir, "testConfig.json")
	dbconfig := filepath.Join(dir, "cop-db.json")
	os.Args = []string{"server", "start", "-ca", cert, "-ca-key", key, "-config", config, "-db-config", dbconfig}
	ServerCommand()
	os.Args = osArgs

}

// StartCommand assembles the definition of Command 'serve'
var StartCommand = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: startMain}
