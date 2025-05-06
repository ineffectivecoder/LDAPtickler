package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
	"github.com/mjwhitta/cli"
	"golang.org/x/term"
)

// Flags
var flags struct {
	anonymous  bool
	ldapURL    string
	skipVerify bool
	username   string
}

// Globals
var password string

func init() {
	var bytepw []byte
	var err error
	// Configure cli package
	cli.Align = true // Defaults to false
	cli.Authors = []string{"Chris Hodson r2d2@sostup.id"}
	cli.Banner = fmt.Sprintf("%s [OPTIONS] <arg>", os.Args[0])
	cli.Info("A tool to simplify LDAP queries because it sucks and is not fun")

	// Parse cli flags
	cli.Flag(&flags.anonymous, "a", "anonymous", false, "Bind Anonymously")
	cli.Flag(&flags.ldapURL, "l", "ldapurl", "", "LDAP(S) URL to connect to")
	cli.Flag(&flags.skipVerify, "s", "skip", false, "Skip SSL verification")
	cli.Flag(&flags.username, "u", "user", "", "Username to bind with")
	cli.Parse()

	// Check for ldapURL, because wtf are we going to connect to without it
	if flags.ldapURL == "" {
		cli.Usage(1)
	}
	// Ensure we are passing no arguments. There shouldnt be any. Only parameters.
	if cli.NArg() > 0 {
		cli.Usage(1)
	}
	/* If a username is passed, assume they also want to use a password. Utilize term.ReadPassword to do this
	without an echo. Passwords as a parameter is bad opsec. May use environment variables as an alternative
	down the road*/
	if flags.anonymous && flags.username != "" {
		fmt.Printf("[-] One does not simply bind anonymously and with credentials - Sean Bean")
		os.Exit(1)
	}
	if flags.username != "" {
		fmt.Printf("[+] Username detected, Insert your password to be used for bind\n")
		bytepw, err = term.ReadPassword(int(os.Stdin.Fd()))
		password = string(bytepw)
		if err != nil {
			fmt.Printf("[-] Last received error message %s", err)
			os.Exit(2)
		}
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

	fmt.Printf("Username is %s\n", flags.username)
	fmt.Printf("Password is %s\n", password)
	defer l.Close()
}
