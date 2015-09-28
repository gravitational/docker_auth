/*
   Copyright 2015 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type DBAuthConfig struct {
	Driver         string `yaml:"driver,omitempty"`
	DataSourceName string `yaml:"data_source_name,omitempty"`
}

type dbAuth struct {
	db *sqlx.DB
}

type User struct {
	Account  string `db:"account"`
	Password string `db:"password"`
}

func NewDBAuth(config *DBAuthConfig) (*dbAuth, error) {
	db, err := sqlx.Connect(config.Driver, config.DataSourceName)
	if err != nil {
		return nil, err
	}

	return &dbAuth{
		db: db,
	}, nil
}

func (d *dbAuth) Authenticate(user string, password PasswordString) (bool, error) {
	users := []User{}
	if err := d.db.Select(&users, fmt.Sprintf("SELECT * FROM users where account=%s", user)); err != nil {
		return false, err
	}

	if len(users) == 0 {
		return false, NoMatch
	}

	if len(users) > 1 {
		return false, errors.New("Integrity error: there are more than one users with this username")
	}

	if bcrypt.CompareHashAndPassword([]byte(users[0].Password), []byte(password)) != nil {
		return false, nil
	}

	return true, nil
}

func (d *dbAuth) Stop() {
	if err := d.db.Close(); err != nil {
		glog.Errorf("error closing db: %v", err)
	}
}

func (d *dbAuth) Name() string {
	return "db_auth"
}
