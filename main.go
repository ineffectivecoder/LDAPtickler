package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/go-ldap/ldap/v3"
	"github.com/mjwhitta/cli"
	"golang.org/x/term"
)

// Flags
var flags struct {
	skipVerify bool
	ldapURL    string
	username   string
	password   bool
}

// Globals
var bytepw []byte
var err error

func init() {
	// Configure cli package
	cli.Align = true // Defaults to false
	cli.Authors = []string{"Chris Hodson r2d2@sostup.id"}
	cli.Banner = fmt.Sprintf("%s [OPTIONS] <arg>", os.Args[0])
	cli.Info("A tool to simplify LDAP queries because it sucks and is not fun")

	// Parse cli flags
	cli.Flag(&flags.skipVerify, "k", "skip", false, "Skip SSL verification")
	cli.Flag(&flags.ldapURL, "s", "", "LDAP(S) URL to connect to")
	cli.Flag(&flags.username, "u", "", "Username to bind with")
	cli.Parse()

	// Check for ldapURL, because wtf are we going to connect to without it
	if flags.ldapURL == "" {
		cli.Usage(1)
	}
	if cli.NArg() > 0 {
		cli.Usage(1)
	}
	if flags.username != "" {

		fmt.Printf("[+] Username detected, Insert your password to be used for bind\n")
		bytepw, err = term.ReadPassword(syscall.Stdin)

	}
}

func main() {
	fmt.Printf("[+] skipVerify currently set to %t\n", flags.skipVerify)
	l, err := ldap.DialURL(flags.ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: flags.skipVerify}))
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("[+] We have successfully connected to %s\n", flags.ldapURL)
	}
	pass := string(bytepw)
	fmt.Printf("Username is %s\n", flags.username)
	fmt.Printf("Password is %s\n", pass)
	defer l.Close()
}
