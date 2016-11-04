package server

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-cop/cli/cop/config"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

type Bootstrap struct {
	db         *sqlx.DB
	dbAccessor *Accessor
	cfg        *config.Config
}

func BootstrapDB(db *sqlx.DB, cfg *config.Config) *Bootstrap {
	b := new(Bootstrap)
	b.db = db
	b.dbAccessor = NewDBAccessor()
	b.dbAccessor.SetDB(b.db)
	b.cfg = cfg
	return b
}

func (b *Bootstrap) PopulateUsersTable() error {
	log.Debug("populateUsersTable")
	for name, info := range b.cfg.Users {
		metaDataBytes, _ := json.Marshal(info.Attributes)

		id := name
		userType := info.Type
		group := info.Group
		metadata := string(metaDataBytes)
		registrar := ""
		pass := info.Pass

		reg := NewRegisterUser()
		reg.RegisterUser(id, userType, group, metadata, registrar, pass)
	}
	return nil
}

func (b *Bootstrap) populateGroup(name, parent, key string, level int, db *sqlx.DB) {
	registerGroup(name, parent, db)
	newKey := key + "." + name

	if level == 0 {
		affiliationGroups := viper.GetStringSlice(newKey)
		for ci := range affiliationGroups {
			registerGroup(affiliationGroups[ci], name, db)
		}
	} else {
		affiliationGroups := viper.GetStringMapString(newKey)
		for childName := range affiliationGroups {
			b.populateGroup(childName, name, newKey, level-1, db)
		}
	}
}

// populateAffiliationGroupsTable populates affiliation groups table.
func (b *Bootstrap) PopulateGroupsTable() {
	log.Debug("PopulateGroupsTable")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName("cop")
	viper.SetConfigType("json")
	viper.AddConfigPath("./")

	configPath := filepath.Dir(b.cfg.ConfigFile)
	viper.AddConfigPath(configPath)
	err := viper.ReadInConfig()
	if err != nil {
		log.Errorf("Fatal error when reading cop config file: %s", err)
	}

	key := "groups"
	affiliationGroups := viper.GetStringMapString(key)
	for name := range affiliationGroups {
		b.populateGroup(name, "", key, 1, b.db)
	}
}

func registerGroup(name string, parentName string, db *sqlx.DB) error {
	mutex.Lock()
	defer mutex.Unlock()

	log.Debug("Registering affiliation group " + name + " parent " + parentName + ".")

	dbAccessor := NewDBAccessor()
	dbAccessor.SetDB(db)

	var err error
	_, _, err = dbAccessor.GetGroup(name)
	if err == nil {
		log.Error("Group already registered")
		return errors.New("Group already registered")
	}

	err = dbAccessor.InsertGroup(name, parentName)
	if err != nil {
		log.Error(err)
	}

	return err

}
