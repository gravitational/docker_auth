// Package db provides a set of common functions and structures for interacting
// with the database that the auth server uses.
package db

type User struct {
	Account  string `db:"account"`
	Password string `db:"password"`
}

type Acl struct {
	ID      uint64 `db:"id"`
	Account string `db:"account"`
	Type    string `db:"type"`
	Name    string `db:"name"`
	// I would like Actions to be a list of strings, but it appears that there is
	// some bug in the DB driver the causes improper deserialization if []string
	// is used.  So Actions will be a string like "{pull, push}"
	Actions string `db:"actions"`
}

type DBAuthConfig struct {
	Driver         string `yaml:"driver,omitempty"`
	DataSourceName string `yaml:"data_source_name,omitempty"`
}
