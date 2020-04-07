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

func GetOrgUnits(dn string) []string {
	r := regexp.MustCompile(`OU=([^,]*)`)
	if !r.MatchString(dn) {
		return nil
	}
	w := r.FindAllStringSubmatch(dn, -1)
	out := make([]string, len(w), len(w))
	for i := range w {
		out[i] = w[i][1]
	}
	return out
}
