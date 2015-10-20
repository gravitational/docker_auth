package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app        = kingpin.New("auth-client", "CLI client for interacting with the auth server")
	insecure   = app.Flag("insecure", "Skip certificate checks").Bool()
	serverAddr = app.Flag("addr", "address of the auth server").Default("https://auth.gravitational.io").Short('a').URL()

	ccreateUser         = app.Command("create-user", "Create a new user")
	ccreateUserUsername = ccreateUser.Flag("username", "Username of the user being created").Short('u').Required().OverrideDefaultFromEnvar("AUTH_USERNAME").String()
	ccreateUserPassword = ccreateUser.Flag("password", "Password of the user being created").Short('p').Required().OverrideDefaultFromEnvar("AUTH_PASSWORD").String()

	clistUser = app.Command("list-user", "List all users")

	cremoveUser         = app.Command("remove-user", "Remove a user")
	cremoveUserUsername = cremoveUser.Arg("username", "Username of the user being removed").Required().String()

	ccreateACL        = app.Command("create-acl", "Create a new ACL")
	ccreateACLAccount = ccreateACL.Flag("username", "Username of the user that this ACL is for").Short('u').Required().String()
	ccreateACLType    = ccreateACL.Flag("type", "Type of the ACL").Short('t').Required().String()
	ccreateACLName    = ccreateACL.Flag("name", "Name of the repo").Short('n').Required().String()
	ccreateACLActions = ccreateACL.Flag("actions", "Actions that the user can apply to the repo").Required().Strings()

	clistACL = app.Command("list-acl", "List all ACLs")

	cremoveACL   = app.Command("remove-acl", "Remove a ACL")
	cremoveACLID = cremoveACL.Arg("ID", "Username of the user being removed").Required().Int()
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
	case clistUser.FullCommand():
		err = c.listUser()
	case cremoveUser.FullCommand():
		err = c.removeUser(*cremoveUserUsername)
	case ccreateACL.FullCommand():
		err = c.createACL(*ccreateACLAccount, *ccreateACLType, *ccreateACLName, *ccreateACLActions)
	case clistACL.FullCommand():
		err = c.listACL()
	case cremoveACL.FullCommand():
		err = c.removeACL(*cremoveACLID)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "auth-client error: %v\n", err)
		os.Exit(-1)
	}
}

func printResp(resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf(string(body))
	return nil
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

	return printResp(resp)
}

func (c *client) listUser() error {
	resp, err := c.client.Get(c.addr.String() + "/list_user")
	if err != nil {
		return err
	}

	return printResp(resp)
}

func (c *client) removeUser(username string) error {
	if username == "" {
		return errors.New("username was empty")
	}

	resp, err := c.client.PostForm(c.addr.String()+"/remove_user", url.Values{
		"account": {username},
	})
	if err != nil {
		return err
	}

	return printResp(resp)
}

func (c *client) createACL(account string, typ string, name string, actions []string) error {
	resp, err := c.client.PostForm(c.addr.String()+"/create_acl", url.Values{
		"account": {account},
		"type":    {typ},
		"name":    {name},
		"actions": {fmt.Sprintf("{%s}", strings.Join(actions, ","))},
	})
	if err != nil {
		return err
	}

	return printResp(resp)
}

func (c *client) listACL() error {
	resp, err := c.client.Get(c.addr.String() + "/list_acl")
	if err != nil {
		return err
	}

	return printResp(resp)
}

func (c *client) removeACL(ID int) error {
	resp, err := c.client.PostForm(c.addr.String()+"/remove_acl", url.Values{
		"ID": {strconv.Itoa(ID)},
	})
	if err != nil {
		return err
	}

	return printResp(resp)
}
