package ldap

import "testing"

func TestGetNameFromDN(t *testing.T) {
	in := "CN=Some Guy,OU=Operations,OU=MYC Users,DC=myc,DC=mycompany,DC=net"
	out := "Some Guy"
	res := GetNameFromDN(in)
	if out != res {
		t.Error("wrong name was found ", res)
	}
}

func TestGetNameFromDN_end(t *testing.T) {
	in := "OU=Operations,OU=MYC Users,DC=myc,DC=mycompany,DC=net,CN=Some Guy"
	out := "Some Guy"
	res := GetNameFromDN(in)
	if out != res {
		t.Error("wrong name was found ", res)
	}
}

func TestGetNameFromDN_only(t *testing.T) {
	in := "CN=Some Guy"
	out := "Some Guy"
	res := GetNameFromDN(in)
	if out != res {
		t.Error("wrong name was found ", res)
	}
}

func TestGetNameFromDN_no(t *testing.T) {
	in := "OU=Operations,OU=MYC Users,DC=myc,DC=mycompany,DC=net"
	out := ""
	res := GetNameFromDN(in)
	if out != res {
		t.Error("wrong name was found ", res)
	}
}
