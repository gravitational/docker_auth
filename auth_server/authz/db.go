package authz

import (
	"database/sql"
	"strings"

	"github.com/cesanta/docker_auth/auth_server/db"
	"github.com/jmoiron/sqlx"
)

type dbAuthorizer struct {
	config *db.DBAuthConfig
}

func NewDBAuth(config *db.DBAuthConfig) *dbAuthorizer {
	return &dbAuthorizer{config: config}
}

func (d *dbAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	conn, err := sqlx.Connect(d.config.Driver, d.config.DataSourceName)
	if err != nil {
		return nil, err
	}

	matchedEntry := db.Acl{}
	if err := conn.Get(&matchedEntry, "SELECT * FROM acls where $1 ~ account AND $2 ~ type AND $3 ~ name", ai.Account, ai.Type, ai.Name); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		} else {
			return nil, NoMatch
		}
	}

	// Get rid of the leading and trailing brackets
	matchedEntry.Actions = matchedEntry.Actions[1 : len(matchedEntry.Actions)-1]
	actions := strings.Split(matchedEntry.Actions, ", ")

	if len(actions) == 1 && (actions)[0] == "*" {
		return ai.Actions, nil
	}

	return StringSetIntersection(ai.Actions, actions), nil
}

func (d *dbAuthorizer) Stop() {}

func (d *dbAuthorizer) Name() string {
	return "DB ACL"
}
