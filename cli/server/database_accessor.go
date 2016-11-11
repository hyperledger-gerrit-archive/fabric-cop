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
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"

	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
	_ "github.com/mattn/go-sqlite3"
)

// Match to sqlx
func init() {
	sqlstruct.TagName = "db"
}

const (
	insertUser = `
INSERT INTO users (id, enrollment_id, token, type, metadata, state, key, serial_number)
	VALUES (:id, :enrollment_id, :token, :type, :metadata, :state, :key, :serial_number);`

	deleteUser = `
DELETE FROM users
	WHERE (id = ?);`

	updateUser = `
UPDATE users
	SET token = :token, metadata = :metadata, state = :state, serial_number = :serial_number
	WHERE (id = :id);`

	getUser = `
SELECT * FROM users
	WHERE (id = ?)`

	insertGroup = `INSERT INTO groups (name, parent_id) VALUES (?, ?)`

	deleteGroup = `
DELETE FROM groups
	WHERE (name = ?)`

	getGroup = `SELECT * FROM groups WHERE (name = ?)`
)

// Accessor implements db.Accessor interface.
type Accessor struct {
	db *sqlx.DB
}

type Group struct {
	Name     string `db:"name"`
	ParentID string `db:"parent_id"`
}

func (d *Accessor) checkDB() error {
	if d.db == nil {
		return errors.New("unknown db object, please check SetDB method")
	}
	return nil
}

func NewDBAccessor() *Accessor {
	return &Accessor{}
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *Accessor) SetDB(db *sqlx.DB) {
	d.db = db
	return
}

func (d *Accessor) InsertUser(user cop.UserRecord) error {
	log.Debugf("DB: Inserting user (%s)...", user.ID)
	err := d.checkDB()
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(insertUser, &cop.UserRecord{
		ID:           user.ID,
		EnrollmentID: user.EnrollmentID,
		Token:        user.Token,
		Type:         user.Type,
		Metadata:     user.Metadata,
		State:        user.State,
		Key:          user.Key,
		SerialNumber: user.SerialNumber,
	})

	if err != nil {
		log.Error("Failed to insert user, error: ", err)
		return err
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return cop.NewError(cop.UserStoreError, "failed to insert the user record")
	}

	if numRowsAffected != 1 {
		return cop.NewError(cop.UserStoreError, "%d rows are affected, should be 1 row", numRowsAffected)
	}

	return err

}

func (d *Accessor) DeleteUser(id string) error {
	err := d.checkDB()
	if err != nil {
		return err
	}

	_, err = d.db.Exec(deleteUser, id)
	if err != nil {
		return err
	}

	return nil
}

func (d *Accessor) UpdateUser(user cop.UserRecord) error {
	err := d.checkDB()
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(updateUser, &cop.UserRecord{
		ID:           user.ID,
		Token:        user.Token,
		State:        user.State,
		Metadata:     user.Metadata,
		SerialNumber: user.SerialNumber,
	})

	if err != nil {
		return err
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return cop.NewError(cop.UserStoreError, "failed to update the user record")
	}

	if numRowsAffected != 1 {
		return cop.NewError(cop.UserStoreError, "%d rows are affected, should be 1 row", numRowsAffected)
	}

	return err

}

func (d *Accessor) GetUser(id string) (cop.UserRecord, error) {
	err := d.checkDB()
	var User cop.UserRecord
	if err != nil {
		return User, err
	}

	err = d.db.Get(&User, d.db.Rebind(getUser), id)
	if err != nil {
		log.Debugf("User (%s), error: %s", id, err)
		return User, err
	}

	return User, nil
}

func (d *Accessor) InsertGroup(name string, parentID string) error {
	err := d.checkDB()
	if err != nil {
		return err
	}

	log.Debugf("DB - Query: %s, args: %s, %s", fmt.Sprint(d.db.Rebind(insertGroup)), name, parentID)
	_, err = d.db.Exec(d.db.Rebind(insertGroup), name, parentID)
	if err != nil {
		return err
	}

	return nil
}

func (d *Accessor) DeleteGroup(name string) error {
	err := d.checkDB()
	if err != nil {
		return err
	}

	_, err = d.db.Exec(deleteGroup, name)
	if err != nil {
		return err
	}

	return nil
}

func (d *Accessor) GetGroup(name string) (string, string, error) {
	err := d.checkDB()
	if err != nil {
		return "", "", err
	}

	group := Group{}

	log.Debugf("DB - Query: %s, args: %s", fmt.Sprint(d.db.Rebind(getGroup)), name)
	err = d.db.Get(&group, d.db.Rebind(getGroup), name)
	if err != nil {
		return "", "", err
	}

	return group.Name, group.ParentID, err
}
