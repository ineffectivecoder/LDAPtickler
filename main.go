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
	basedn                  string
	computers               bool
	constraineddelegation   bool
	domain                  string
	domaincontrollers       bool
	filter                  string
	kerberoastable          bool
	ldapURL                 string
	nopassword              bool
	password                bool
	passwordontexpire       bool
	passwordchangenextlogin bool
	preauthdisabled         bool
	pth                     string
	protectedusers          bool
	rbcd                    bool
	shadowcredentials       bool
	skipVerify              bool
	username                string
	unconstraineddelegation bool
	users                   bool
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
	cli.Flag(&flags.constraineddelegation, "cd", false, "Search for all objects configured for Constrained Delegation")
	cli.Flag(&flags.domaincontrollers, "dc", false, "Search for all Domain Controllers")
	cli.Flag(&flags.domain, "d", "domain", "", "Domain for NTLM bind")
	cli.Flag(&flags.filter, "f", "filter", "", "Specify your own filter. ex. (objectClass=computer)")
	cli.Flag(&flags.kerberoastable, "kerberoastable", false, "Search for kerberoastable users")
	cli.Flag(&flags.ldapURL, "l", "ldapurl", "", "LDAP(S) URL to connect to")
	cli.Flag(&flags.nopassword, "np", false, "Search for users not required to have a password")
	cli.Flag(&flags.password, "p", "password", false, "Password to bind with, will prompt")
	cli.Flag(&flags.passwordontexpire, "pde", false, "Search for objects where the password doesnt expire")
	cli.Flag(&flags.passwordchangenextlogin, "pcnl", false, "Search for objects where the password is required to be changed at next login")
	cli.Flag(&flags.protectedusers, "pu", false, "Search for users in Protected Users group")
	cli.Flag(&flags.pth, "pth", "", "Bind with password hash, WHY IS THIS SUPPORTED OTB?!")
	cli.Flag(&flags.preauthdisabled, "pad", false, "Search for users with Kerberos Pre-auth Disabled")
	cli.Flag(&flags.rbcd, "rbcd", false, "Search for  all objects configured with Resource Based Constrained Delegation")
	cli.Flag(&flags.skipVerify, "s", "skip", false, "Skip SSL verification")
	cli.Flag(&flags.shadowcredentials, "sc", false, "Search for all objects with Shadow Credentials")
	cli.Flag(&flags.unconstraineddelegation, "ud", false, "Search for all objects configured for Unconstrained Delegation")
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
func ldapsearch(l *ldap.Conn, filter string, attributes []string) {
	searchReq := ldap.NewSearchRequest(flags.basedn, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, attributes, []ldap.Control{})
	result, err := l.Search(searchReq)
	check(err)
	result.PrettyPrint(3)
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
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.constraineddelegation {
		fmt.Printf("[+] Searching for all Constrained Delegation objects in LDAP with baseDN %s", flags.basedn)
		filter := "(&(objectClass=User)(msDS-AllowedToDelegateTo=*))"
		attributes := []string{"samaccountname", "msDS-AllowedToDelegateTo"}
		ldapsearch(l, filter, attributes)
	}

	if flags.domaincontrollers {
		fmt.Printf("[+] Searching for all Domain Controllers in LDAP with baseDN %s", flags.basedn)
		filter := "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.filter != "" {
		fmt.Printf("[+] Searching with specified filter: %s in LDAP with baseDN %s", flags.filter, flags.basedn)
		filter := flags.filter
		attributes := []string{}
		ldapsearch(l, filter, attributes)
	}

	if flags.kerberoastable {
		fmt.Printf("[+] Searching for all Kerberoastable users in LDAP with baseDN %s", flags.basedn)
		filter := "(&(objectClass=User)(serviceprincipalname=*)(samaccountname=*))"
		attributes := []string{"samaccountname", "serviceprincipalname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.nopassword {
		fmt.Printf("[+] Searching for all users not required to have a password in LDAP with baseDN %s", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.passwordontexpire {
		fmt.Printf("[+] Searching for all users all objects where the password doesnt expire in LDAP with baseDN %s", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.passwordchangenextlogin {
		fmt.Printf("[+] Searching for all users all objects where the password is set to change at next login in LDAP with baseDN %s", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.protectedusers {
		fmt.Printf("[+] Searching for all users in Protected Users group in LDAP with baseDN %s", flags.basedn)
		filter := "(&(samaccountname=Protect*)(member=*))"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.preauthdisabled {
		fmt.Printf("[+] Searching for all Kerberos Pre-auth Disabled users in LDAP with baseDN %s", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.rbcd {
		fmt.Printf("[+] Searching for all Resource Based Constrained Delegation objects in LDAP with baseDN %s", flags.basedn)
		filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
		attributes := []string{"samaccountname", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
		ldapsearch(l, filter, attributes)
	}

	if flags.shadowcredentials {
		fmt.Printf("[+] Searching for all Shadow Credentials in LDAP with baseDN %s", flags.basedn)
		filter := "(msDS-KeyCredentialLink=*)"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.unconstraineddelegation {
		fmt.Printf("[+] Searching for all Unconstrained Delegation objects in LDAP with baseDN %s", flags.basedn)
		filter := "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

	if flags.users {
		fmt.Printf("[+] Searching for all users in LDAP with baseDN %s", flags.basedn)
		filter := "(objectClass=user)"
		attributes := []string{"samaccountname"}
		ldapsearch(l, filter, attributes)
	}

}
