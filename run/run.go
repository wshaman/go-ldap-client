package main

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/wshaman/go-ldap-client"
)

func getClient() *ldap.Client {
	client := &ldap.Client{
		Base:               os.Getenv("LDAP_BASE"),
		Host:               os.Getenv("LDAP_HOST"),
		BindDN:             os.Getenv("LDAP_USER"),
		BindPassword:       os.Getenv("LDAP_PWD"),
		Port:               3269,
		UseSSL:             true,
		InsecureSkipVerify: true,
		UserFilter:         "(|(sAMAccountName=%[1]s)(mail=%[1]s)(givenName=%[1]s))",
		GroupFilter:        "(memberUid=%s)",
		Attributes: []string{"givenName", "sn", "mail", "sAMAccountName", "organizationalRole", "objectCategory",
			"objectClass", "title", "description"},
	}
	return client
}

func main() {
	f, err := os.OpenFile(path.Join(os.TempDir(), "/users.csv"), os.O_CREATE|os.O_WRONLY, 0722)
	if err != nil {
		panic(err)
	}
	c := getClient()
	if err := c.Connect(); err != nil {
		panic(err)
	}
	r, err := c.SearchUsers("jacob.lawyer*", 500)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(f, "Email;Name;LastName;Manager;OU;Title;description;objectClass;objectCategory")
	for _, v := range r {

		if !v.IsActive || (v.LastName == "" && v.GivenName == "") {
			continue
		}
		fmt.Fprintf(f, "%s;%s;%s;%s;%s;%s;%s;%s;%s\n", v.Email, v.GivenName, v.LastName, v.Manager,
			strings.Join(v.OrganisationUnits, ","), v.Attributes["title"], v.Attributes["description"],
			v.Attributes["objectClass"], v.Attributes["objectCategory"])
	}
	f.Close()
}
