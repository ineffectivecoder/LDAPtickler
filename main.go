package main

import (
	"crypto/tls"
	"log"

	"github.com/go-ldap/ldap/v3"
)

func main() {
	ldapURL := "ldaps://dc01.ad.sostup.id:636"
	l, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
