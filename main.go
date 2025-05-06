package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
	"github.com/mjwhitta/cli"
)

// Flags
var flags struct {
	sslVerify bool
	ldapURL   string
}

func init() {
	// Configure cli package
	cli.Align = true // Defaults to false
	cli.Authors = []string{"Chris Hodson r2d2@sostup.id"}
	cli.Banner = fmt.Sprintf("%s [OPTIONS] <arg>", os.Args[0])
	cli.Info("A tool to simplify LDAP queries because it sucks and is not fun")

	// Parse cli flags
	cli.Flag(&flags.sslVerify, "b", "bool", false, "Verify cert?")
	cli.Flag(&flags.ldapURL, "s", "", "LDAP URL to connect to")
	cli.Parse()

	// Validate cli args
	if cli.NArg() == 0 {
		cli.Usage(1)
	} else if cli.NArg() > 1 {
		cli.Usage(1)
	} else if flags.ldapURL == "" {
		cli.Usage(1)
	}
}

func main() {
	//ldapURL := "ldaps://dc01.ad.sostup.id:636"
	l, err := ldap.DialURL(flags.ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: flags.sslVerify}))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
