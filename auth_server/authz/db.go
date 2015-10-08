package authz

import (
	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/jmoiron/sqlx"
)

type dbAuthorizer struct {
	config *authn.DBAuthConfig
}

type Acl struct {
	Account string   `db:"account"`
	Type    string   `db:"type"`
	Name    string   `db:"name"`
	Actions []string `db:"actions"`
}

func NewDBAuth(config *authn.DBAuthConfig) *dbAuthorizer {
	return &dbAuthorizer{config: config}
}

func (d *dbAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	db, err := sqlx.Connect(d.config.Driver, d.config.DataSourceName)
	if err != nil {
		return nil, err
	}

	matchedEntry := Acl{}
	if db.Get(&matchedEntry, "SELECT * FROM acls where $1 SIMILAR TO account AND $2 SIMILAR TO type AND $3 SIMILAR TO name", ai.Account, ai.Type, ai.Name); err != nil {
		return nil, err
	}

	if len(matchedEntry.Actions) == 1 && (matchedEntry.Actions)[0] == "*" {
		return ai.Actions, nil
	}

	return StringSetIntersection(ai.Actions, matchedEntry.Actions), nil
}

func (d *dbAuthorizer) Stop() {}

func (d *dbAuthorizer) Name() string {
	return "DB ACL"
}
