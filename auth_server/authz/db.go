package authz

import (
	"strings"

	"github.com/cesanta/docker_auth/auth_server/db"
	"github.com/golang/glog"
	"github.com/jmoiron/sqlx"
)

var (
	log = glog.V(2)
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
		return nil, err
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
