package main

import (
	"fmt"
	"os"

	"github.com/wshaman/go-ldap-client"
)

func getClient() *ldap.LDAPClient {
	client := &ldap.LDAPClient{
		Base:               os.Getenv("LDAP_BASE"),
		Host:               os.Getenv("LDAP_HOST"),
		BindDN:             os.Getenv("LDAP_USER"),
		BindPassword:       os.Getenv("LDAP_PWD"),
		Port:               3269,
		UseSSL:             true,
		InsecureSkipVerify: true,
		UserFilter:         "(|(sAMAccountName=%[1]s)(mail=%[1]s))",
		GroupFilter:        "(memberUid=%s)",
		Attributes:         []string{"givenName", "sn", "mail", "sAMAccountName"},
	}
	return client
}

func main() {
	c := getClient()
	if err := c.Connect(); err != nil {
		panic(err)
	}
	t, r, err := c.SearchUsers("")
	if err != nil {
		panic(err)
	}
	fmt.Println(t)
	fmt.Println(r)
}
