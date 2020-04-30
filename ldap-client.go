// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/ldap.v2"
)

type Client struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
}

type Person struct {
	DN                string
	IsActive          bool
	GivenName         string
	LastName          string
	Email             string
	Title             string
	Manager           string
	Attributes        map[string]string
	OrganisationUnits []string
}

func (lc *Client) addDefaultAttributes() {
	def := []string{"dn", "givenName", "sn", "mail", "title"}
	exists := map[string]bool{}
	for _, v := range lc.Attributes {
		exists[v] = true
	}
	for _, v := range def {
		if _, ok := exists[v]; ok {
			continue
		}
		lc.Attributes = append(lc.Attributes, v)
	}
}

// Connect connects to the ldap backend.
func (lc *Client) Connect() error {
	if lc.Conn == nil {
		lc.addDefaultAttributes()
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection.
func (lc *Client) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// Authenticate authenticates the user against the ldap backend.
func (lc *Client) Authenticate(username, password string) (bool, *Person, error) {
	err := lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := personFromSearchEntry(sr.Entries[0], attributes)

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return false, &user, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, &user, err
		}
	}

	return true, &user, nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *Client) GetGroupsOfUser(username string) ([]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, username),
		[]string{"cn"}, // can it be something else than "cn"?
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

// SearchUsers returns the group for a user.
func (lc *Client) SearchUsers(namePart string, pageSize int) ([]Person, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}
	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return nil, err
		}
	}

	attributes := append(lc.Attributes, "dn", "manager")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, namePart),
		attributes,
		nil,
	)

	sr, err := lc.Conn.SearchWithPaging(searchRequest, uint32(pageSize))
	if err != nil {
		return nil, err
	}

	users := make([]Person, 0)
	for _, v := range sr.Entries {
		user := personFromSearchEntry(v, attributes)
		users = append(users, user)
	}
	return users, nil
}

func personFromSearchEntry(v *ldap.Entry, attributes []string) Person {
	user := Person{DN: v.DN,
		IsActive:   !isDeactivatedUser(v.DN),
		Attributes: map[string]string{},
	}
	for _, attr := range attributes {
		user.Attributes[attr] = v.GetAttributeValue(attr)
	}
	user.LastName = user.Attributes["sn"]
	user.GivenName = user.Attributes["givenName"]
	user.Email = user.Attributes["mail"]
	user.Title = user.Attributes["title"]
	user.Manager = GetNameFromDN(user.Attributes["manager"])
	user.OrganisationUnits = GetOrgUnits(v.DN)
	return user
}

//Thank you, Trevor!
func isDeactivatedUser(dn string) bool {
	return strings.Contains(dn, "Deprovisioned") || strings.Contains(dn, "OU=Disabled Users")
}
