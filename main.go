package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/mjwhitta/cli"
	"golang.org/x/term"
)

type bindMode int

const (
	bindAnonymous = iota
	bindPassword
	bindDomain
	bindDomainPTH
	bindSASL
	bindGSSAPI
)

// Global state
var state struct {
	mode     bindMode
	password string
}

// Flags
var flags struct {
	basedn         string
	computers      bool
	domain         string
	filter         string
	kerberoastable bool
	ldapURL        string
	password       bool
	pth            string
	skipVerify     bool
	username       string
	users          bool
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func init() {
	var bytepw []byte
	var err error
	// Configure cli package
	cli.Align = true // Defaults to false
	cli.Authors = []string{"Chris Hodson r2d2@sostup.id"}
	cli.Banner = fmt.Sprintf("%s [OPTIONS] <arg>", os.Args[0])
	cli.Info("A tool to simplify LDAP queries because it sucks and is not fun")

	// Parse cli flags
	cli.Flag(&flags.basedn, "b", "basedn", "", "Specify baseDN for query, ex. ad.sostup.id would be dc=ad,dc=sostup,dc=id")
	cli.Flag(&flags.computers, "computers", false, "Search for all Computer objects")
	cli.Flag(&flags.domain, "d", "domain", "", "Domain for NTLM bind")
	cli.Flag(&flags.filter, "f", "filter", "", "Specify your own filter. ex. (objectClass=computer)")
	cli.Flag(&flags.kerberoastable, "kerberoastable", false, "Search for kerberoastable users")
	cli.Flag(&flags.ldapURL, "l", "ldapurl", "", "LDAP(S) URL to connect to")
	cli.Flag(&flags.password, "p", "password", false, "Password to bind with, will prompt")
	cli.Flag(&flags.pth, "pth", "", "Bind with password hash, WHY IS THIS SUPPORTED OTB?!")
	cli.Flag(&flags.skipVerify, "s", "skip", false, "Skip SSL verification")
	cli.Flag(&flags.username, "u", "user", "", "Username to bind with")
	cli.Flag(&flags.users, "users", false, "Search for all User objects")

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
	if flags.password {
		state.mode = bindPassword
		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
		fmt.Printf("[+] Enter Password:")
		bytepw, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()

		if err != nil {
			log.Fatalf("[-] Last received error message %s", err)
		}
		state.password = string(bytepw)
	}
	if flags.domain != "" {
		state.mode = bindDomain
		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
	}

	if flags.pth != "" {
		state.mode = bindDomainPTH
		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
	}

}

// Eventually build this up to take all supported parameters, just an initial shell so far with support for filter.
func ldapsearch(l *ldap.Conn, filter string) {
	searchReq := ldap.NewSearchRequest(flags.basedn, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{}, []ldap.Control{})
	result, err := l.Search(searchReq)
	check(err)
	result.Print()
}

func main() {
	var l *ldap.Conn
	var err error
	fmt.Printf("[+] skipVerify currently set to %t\n", flags.skipVerify)
	if strings.HasPrefix(flags.ldapURL, "ldaps:") {
		l, err = ldap.DialURL(flags.ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: flags.skipVerify}))
	} else {
		l, err = ldap.DialURL(flags.ldapURL)
	}
	check(err)
	defer l.Close()

	// Attempt anonymous bind, check for flag
	switch state.mode {
	case bindAnonymous:
		fmt.Printf("[+] Attempting anonymous bind to %s\n", flags.ldapURL)
		err = l.UnauthenticatedBind(flags.username)

	case bindPassword:
		fmt.Printf("[+] Attempting bind with credentials to %s\n", flags.ldapURL)
		err = l.Bind(flags.username, state.password)

	case bindDomain:
		fmt.Printf("[+] Attempting NTLM bind to %s\n", flags.ldapURL)
		err = l.NTLMBind(flags.domain, flags.username, state.password)

	case bindDomainPTH:
		fmt.Printf("[+] Attempting NTLM Pass The Hash bind to %s\n", flags.ldapURL)
		err = l.NTLMBindWithHash(flags.domain, flags.username, flags.pth)
	}

	check(err)
	fmt.Printf("[+] We have successfully connected to %s\n", flags.ldapURL)

	// We have so much power here with the filters. Basically any filter that works in ldapsearch should work here.
	// In order to simplify searching for varous objects, we will have a reasonable number of flags for things like:
	// computers, users, kerberoastable users. We will also accommodate users who are comfy using their own filter.
	if flags.computers {
		fmt.Printf("[+] Searching for all computers in LDAP with baseDN %s", flags.basedn)
		filter := "(objectClass=computer)"
		ldapsearch(l, filter)
	}

	if flags.users {
		fmt.Printf("[+] Searching for all users in LDAP with baseDN %s", flags.basedn)
		filter := "(objectClass=user)"
		ldapsearch(l, filter)
	}

	if flags.kerberoastable {
		fmt.Printf("[+] Searching for all kerberoastable users in LDAP with baseDN %s", flags.basedn)
		filter := "(&(objectClass=User)(serviceprincipalname=*)(samaccountname=*))"
		ldapsearch(l, filter)
	}
	if flags.filter != "" {
		fmt.Printf("[+] Searching with specified filter: %s in LDAP with baseDN %s", flags.filter, flags.basedn)
		filter := flags.filter
		ldapsearch(l, filter)
	}
}
