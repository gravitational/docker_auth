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

func (d *dbAuth) Authenticate(account string, password PasswordString) (bool, error) {
	var user User
	if err := d.db.Get(&user, "SELECT * FROM users where account=$1", account); err != nil {
		return false, err
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
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
