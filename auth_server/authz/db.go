package authz

import (
	"strings"

	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/golang/glog"
	"github.com/jmoiron/sqlx"
)

var (
	log = glog.V(2)
)

type dbAuthorizer struct {
	config *authn.DBAuthConfig
}

type Acl struct {
	Account string `db:"account"`
	Type    string `db:"type"`
	Name    string `db:"name"`
	// I would like Actions to be a list of strings, but it appears that there is
	// some bug in the DB driver the causes improper deserialization if []string
	// is used.  So Actions will be a string like "{pull, push}"
	Actions string `db:"actions"`
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
	if err := db.Get(&matchedEntry, "SELECT * FROM acls where $1 ~ account AND $2 ~ type AND $3 ~ name", ai.Account, ai.Type, ai.Name); err != nil {
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
