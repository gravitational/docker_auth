package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app        = kingpin.New("auth-client", "CLI client for interacting with the auth server")
	insecure   = app.Flag("insecure", "Skip certificate checks").Bool()
	serverAddr = app.Flag("addr", "address of the auth server").Default("https://auth.gravitational.io").Short('a').URL()

	ccreateUser         = app.Command("create-user", "Create a new user")
	ccreateUserUsername = ccreateUser.Flag("username", "Username of the user being created").Required().OverrideDefaultFromEnvar("AUTH_USERNAME").String()
	ccreateUserPassword = ccreateUser.Flag("password", "Password of the user being created").Required().OverrideDefaultFromEnvar("AUTH_PASSWORD").String()
)

type client struct {
	client *http.Client
	addr   *url.URL // address of the server
}

func main() {
	cmd, err := app.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth-client error: %v\n", err)
		os.Exit(-1)
	}

	c := client{
		addr: *serverAddr,
	}

	if *insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		c.client = &http.Client{Transport: tr}
	} else {
		c.client = &http.Client{}
	}

	switch cmd {
	case ccreateUser.FullCommand():
		err = c.createUser(*ccreateUserUsername, *ccreateUserPassword)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "auth-client error: %v\n", err)
		os.Exit(-1)
	}
}

func (c *client) createUser(username string, password string) error {
	// TODO: possibly more sophisticated constraints?
	if username == "" && password == "" {
		return errors.New("either username or password was empty")
	}

	resp, err := c.client.PostForm(c.addr.String()+"/create_user", url.Values{
		"account":  {username},
		"password": {password},
	})

	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf(string(body))
	return nil
}
