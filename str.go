package ldap

import "regexp"

func GetNameFromDN(dn string) string {
	r := regexp.MustCompile(`CN=([^,]*)`)
	if !r.MatchString(dn) {
		return ""
	}
	w := r.FindAllStringSubmatch(dn, -1)
	return w[0][1]
}
