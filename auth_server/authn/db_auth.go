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
	"github.com/cesanta/docker_auth/auth_server/db"
	"github.com/golang/glog"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type dbAuth struct {
	config *db.DBAuthConfig
}

func NewDBAuth(config *db.DBAuthConfig) *dbAuth {
	return &dbAuth{config: config}
}

func (d *dbAuth) Authenticate(account string, password PasswordString) (bool, error) {
	conn, err := sqlx.Connect(d.config.Driver, d.config.DataSourceName)
	if err != nil {
		return false, err
	}

	var user db.User
	if err := conn.Get(&user, "SELECT * FROM users where account=$1", account); err != nil {
		return false, err
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		return false, nil
	}

	if err := conn.Close(); err != nil {
		glog.Errorf("error closing db: %v", err)
	}
	return true, nil
}

func (d *dbAuth) Stop() {}

func (d *dbAuth) Name() string {
	return "db_auth"
}
