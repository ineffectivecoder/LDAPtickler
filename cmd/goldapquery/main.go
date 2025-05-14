package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	//"github.com/jcmturner/gokrb5/v8/client"
	"git.red.team/silversurfer/goldapquery"
	"github.com/go-ldap/ldap/v3"

	//"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/mjwhitta/cli"
	"golang.org/x/term"
	"golang.org/x/text/encoding/unicode"
)

/*
const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
	// ScopeChildren is an OpenLDAP extension that may not be supported by another directory server.
	// See: https://github.com/openldap/openldap/blob/7c55484ee153047efd0e562fc1638c1a2525f320/include/ldap.h#L598
	ScopeChildren = 3
)
*/

// Global state
var state struct {
	mode     goldapquery.BindMethod
	password string
}

// Flags
var flags struct {
	addmachine              string
	addmachinelowpriv       string
	adduser                 string
	basedn                  string
	certpublishers          bool
	changepassword          string
	computers               bool
	constraineddelegation   bool
	deleteobject            string
	domain                  string
	domaincontrollers       bool
	filter                  string
	groups                  bool
	groupswithmembers       bool
	gssapi                  bool
	kerberoastable          bool
	ldapURL                 string
	machineaccountquota     bool
	nopassword              bool
	objectquery             string
	password                bool
	passwordontexpire       bool
	passwordchangenextlogin bool
	preauthdisabled         bool
	pth                     string
	protectedusers          bool
	querydescription        string
	rbcd                    bool
	schema                  bool
	searchscope             int
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

func encodePassword(password string) string {
	quoted := fmt.Sprintf("\"%s\"", password)
	encoded := ""
	for _, r := range quoted {
		encoded += fmt.Sprintf("%c%c", byte(r), 0)
	}
	return encoded
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

	cli.Flag(&flags.addmachine, "addmachine", "", "Add Machine account, ex computername$ password")
	cli.Flag(&flags.addmachinelowpriv, "lpaddmachine", "", "Add machine account with low priv user. ex computername$ password")
	cli.Flag(&flags.adduser, "adduser", "", "Add a user, ex username username@domain password")
	cli.Flag(&flags.basedn, "b", "basedn", "", "Specify baseDN for query, ex. ad.sostup.id would be dc=ad,dc=sostup,dc=id")
	cli.Flag(&flags.certpublishers, "cert", false, "Search for all CAs in the environment")
	cli.Flag(&flags.changepassword, "cp", "", "Change password for user, must use LDAPS you will need permissions so no funny business. ex. username newpassword")
	cli.Flag(&flags.computers, "computers", false, "Search for all Computer objects")
	cli.Flag(&flags.constraineddelegation, "cd", false, "Search for all objects configured for Constrained Delegation")
	cli.Flag(&flags.deleteobject, "do", "", "Delete an object in AD, initial support for machine accounts and users, ex. machine/user objectname")
	cli.Flag(&flags.domaincontrollers, "dc", false, "Search for all Domain Controllers")
	cli.Flag(&flags.domain, "d", "domain", "", "Domain for NTLM bind")
	cli.Flag(&flags.filter, "f", "filter", "", "Specify your own filter. ex. (objectClass=computer)")
	cli.Flag(&flags.groups, "groups", false, "Search for all group objects")
	cli.Flag(&flags.groupswithmembers, "groupmembers", false, "Search for all groups and their members")
	cli.Flag(&flags.gssapi, "gssapi", false, "Enable GSSAPI and attempt to authenticate")
	cli.Flag(&flags.kerberoastable, "kerberoastable", false, "Search for kerberoastable users")
	cli.Flag(&flags.ldapURL, "l", "ldapurl", "", "LDAP(S) URL to connect to")
	cli.Flag(&flags.machineaccountquota, "maq", false, "Retrieve the attribute ms-DS-MachineAccount Quota to determine how many machine accounts a user may create")
	cli.Flag(&flags.nopassword, "np", false, "Search for users not required to have a password")
	cli.Flag(&flags.objectquery, "oq", "", "Provide all attributes of specific user/computer object, machine accounts will need trailing $")
	cli.Flag(&flags.password, "p", "password", false, "Password to bind with, will prompt")
	cli.Flag(&flags.passwordontexpire, "pde", false, "Search for objects where the password doesnt expire")
	cli.Flag(&flags.passwordchangenextlogin, "pcnl", false, "Search for objects where the password is required to be changed at next login")
	cli.Flag(&flags.protectedusers, "pu", false, "Search for users in Protected Users group")
	cli.Flag(&flags.pth, "pth", "", "Bind with password hash, WHY IS THIS SUPPORTED OTB?!")
	cli.Flag(&flags.preauthdisabled, "pad", false, "Search for users with Kerberos Pre-auth Disabled")
	cli.Flag(&flags.querydescription, "qd", "", "Query all objects for a specific description, useful for finding data like creds in description fields")
	cli.Flag(&flags.rbcd, "rbcd", false, "Search for  all objects configured with Resource Based Constrained Delegation")
	cli.Flag(&flags.schema, "schema", false, "Dump the schema of the LDAP database")
	cli.Flag(&flags.searchscope, "scope", 0, "Define scope of search, 0=Base, 1=Single Level, 2=Whole Sub Tree, 3=Children, only used by filter and objectquery")
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

	/* Various checks for flag combinations that don't make sense.
	Allowing a username for anonymous binds since the spec for LDAP allows it for tracking purposes.
	Reading password using term.ReadPassword to prevent echoing of the credential or needing it in plain text.

	*/

	if flags.password && flags.pth != "" {
		log.Fatal("[-] Silly Goose detected, you cant PTH and provide a password")
	}

	if flags.password {
		state.mode = goldapquery.MethodBindPassword
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
		state.mode = goldapquery.MethodBindDomain
		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
	}

	if flags.pth != "" {
		state.mode = goldapquery.MethodBindDomainPTH
		if flags.domain == "" {
			log.Fatal("[-] Must specify domain to PTH with BindDomain method\n")
		}

		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
	}

	if flags.basedn == "" {
		log.Fatal("[-] A basedn will be required for any action")
	}

	/*if flags.gssapi {
			gssClient, err := gssapi.NewClientWithPassword(
	        flags.username,     // Kerberos principal name
	        flags.domain,    // Kerberos realm
	        state.password,     // Kerberos password
	        "/etc/krb5.conf",    // krb5 configuration file path
	        client.DisablePAFXFAST(true), // Optional: disable FAST if your realm needs it
	    )
		check(err)
		defer gssClient.Close()
		}*/
}

// Eventually build this up to take all supported parameters, just an initial shell so far with support for base, scope, filter and attributes.
func ldapsearch(l *ldap.Conn, base string, searchscope int, filter string, attributes []string) {
	searchReq := ldap.NewSearchRequest(base, searchscope, 0, 0, 0, false, filter, attributes, []ldap.Control{})
	result, err := l.Search(searchReq)
	check(err)
	result.PrettyPrint(2)
}

func main() {
	var l *ldap.Conn
	var err error
	goldapquery.SkipVerify = flags.skipVerify

	// Attempt anonymous bind, check for flag
	switch state.mode {
	case goldapquery.MethodBindAnonymous:
		fmt.Printf("[+] Attempting anonymous bind to %s\n", flags.ldapURL)
		l, err = goldapquery.BindAnonymous(flags.ldapURL, flags.username)

	case goldapquery.MethodBindPassword:
		fmt.Printf("[+] Attempting bind with credentials to %s\n", flags.ldapURL)
		l, err = goldapquery.BindPassword(flags.ldapURL, flags.username, state.password)

	case goldapquery.MethodBindDomain:
		fmt.Printf("[+] Attempting NTLM bind to %s\n", flags.ldapURL)
		l, err = goldapquery.BindDomain(flags.ldapURL, flags.domain, flags.username, state.password)

	case goldapquery.MethodBindDomainPTH:
		fmt.Printf("[+] Attempting NTLM Pass The Hash bind to %s\n", flags.ldapURL)
		l, err = goldapquery.BindDomainPTH(flags.ldapURL, flags.domain, flags.username, flags.pth)

		/*case bindGSSAPI:
		fmt.Printf("[+] Attempting GSSAPI bind to %s\n", flags.ldapURL)
		err = l.GSSAPIBindRequest(gssClient)
		check(err)
		fmt.Println("[+] GSSAPI bind successful")*/
	}
	check(err)
	defer l.Close()
	fmt.Printf("[+] Successfully connected to %s\n", flags.ldapURL)

	// We have so much power here with the filters. Basically any filter that works in ldapsearch should work here.
	// In order to simplify searching for varous objects, we will have a reasonable number of flags for things like:
	// computers, users, kerberoastable users. We will also accommodate users who are comfy using their own filter.
	switch {

	case flags.addmachine != "":
		machinename, machinepass, _ := strings.Cut(flags.addmachine, " ")
		fmt.Printf("[+] Adding machine account %s with password %s\n", machinename, machinepass)
		addReq := ldap.NewAddRequest("CN="+machinename+",CN=Computers,"+flags.basedn, []ldap.Control{})
		addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
		addReq.Attribute("cn", []string{machinename})
		addReq.Attribute("sAMAccountName", []string{machinename + "$"})
		addReq.Attribute("userAccountControl", []string{"4096"}) // WORKSTATION_TRUST_ACCOUNT
		encodedPassword := encodePassword(machinepass)
		addReq.Attribute("unicodePWD", []string{encodedPassword})
		err = l.Add(addReq)
		check(err)
		fmt.Printf("[+] Added machine account %s successfully with password %s\n", machinename, machinepass)

	case flags.addmachinelowpriv != "":
		machinename, machinepass, _ := strings.Cut(flags.addmachinelowpriv, " ")
		fmt.Printf("[+] Adding machine account %s with password %s\n", machinename, machinepass)
		// addReq := ldap.NewAddRequest("CN="+machinename+",CN=Computers,"+flags.basedn, []ldap.Control{})
		// addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
		// addReq.Attribute("sAMAccountName", []string{machinename + "$"})
		// addReq.Attribute("userAccountControl", []string{"4096"}) // WORKSTATION_TRUST_ACCOUNT
		addReq := ldap.NewAddRequest("CN=TESTPC,CN=Computers,DC=ad,DC=sostup,DC=id", nil)
		addReq.Attribute("objectClass", []string{"computer"})
		addReq.Attribute("sAMAccountName", []string{"TESTPC$"})
		addReq.Attribute("userAccountControl", []string{"4096"})
		addReq.Attribute("dNSHostName", []string{"TESTPC.ad.sostup.id"})
		// addReq.Attribute("servicePrincipalName", []string{"HOST/testdudefd.ad.sostup.id", "HOST/testdudefd", "RestrictedKrbHost/testdudefd.ad.sostup.id", "RestrictedKrbHost/testdudefd"})
		// encodedPassword := encodePassword(machinepass)
		// addReq.Attribute("unicodePWD", []string{encodedPassword})
		err = l.Add(addReq)
		check(err)
		fmt.Printf("[+] Added machine account %s with a low priv account successfully with password %s\n", machinename, machinepass)

	case flags.adduser != "":
		detailstopass := strings.Split(flags.adduser, " ")
		fmt.Printf("[+] Adding username %s with serviceprincipal %s with password %s\n", detailstopass[0], detailstopass[1], detailstopass[2])
		addReq := ldap.NewAddRequest("CN="+detailstopass[0]+",CN=Users,"+flags.basedn, []ldap.Control{})
		addReq.Attribute("accountExpires", []string{fmt.Sprintf("%d", 0x00000000)})
		addReq.Attribute("cn", []string{detailstopass[0]})
		addReq.Attribute("displayName", []string{detailstopass[0]})
		addReq.Attribute("givenName", []string{detailstopass[0]})
		addReq.Attribute("instanceType", []string{fmt.Sprintf("%d", 0x00000004)})
		addReq.Attribute("name", []string{detailstopass[0]})
		addReq.Attribute("objectClass", []string{"top", "organizationalPerson", "user", "person"})
		addReq.Attribute("sAMAccountName", []string{detailstopass[0]})
		addReq.Attribute("sn", []string{detailstopass[0]})
		// Create the account disabled....
		addReq.Attribute("userAccountControl", []string{"514"})
		addReq.Attribute("userPrincipalName", []string{detailstopass[1]})
		// addReq.Attributes = attrs
		err = l.Add(addReq)
		check(err)
		fmt.Printf("[+] Successfully added user account %s\n", detailstopass[0])
		fmt.Printf("[+] Now setting password...\n")
		passwordSet := ldap.NewModifyRequest("CN="+detailstopass[0]+",CN=Users,"+flags.basedn, nil)
		utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
		newpwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("%q", detailstopass[2]))
		check(err)
		passwordSet.Replace("unicodePwd", []string{newpwdEncoded})
		// debugging crap
		// log.Printf("The stuff %s", *passwordModify)
		err = l.Modify(passwordSet)
		check(err)
		if err == nil {
			fmt.Printf("[+] Password set successfully for user %s\n", detailstopass[0])
		}
		// You have to create the account disabled, then enable after setting a password... WTF, so intuitive
		fmt.Printf("[+] Now enabling account for user %s\n", detailstopass[0])
		enableReq := ldap.NewModifyRequest("CN="+detailstopass[0]+",CN=Users,"+flags.basedn, []ldap.Control{})
		enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", 0x0200)})
		err = l.Modify(enableReq)
		check(err)
		fmt.Printf("[+] Successfully added and enabled user account %s\n", detailstopass[0])

	case flags.certpublishers:
		fmt.Printf("[+] Searching for all Certificate Publishers in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(samaccountname=Cert Publishers)(member=*) "
		attributes := []string{"member"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.changepassword != "":
		detailstopass := strings.Split(flags.changepassword, " ")
		fmt.Printf("[+] Changing password for user %s with password supplied in LDAP with baseDN %s\n", detailstopass[0], flags.basedn)
		utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
		newpwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("%q", detailstopass[1]))
		check(err)
		passwordModify := ldap.NewModifyRequest("cn="+detailstopass[0]+",cn=Users,"+flags.basedn, nil)
		passwordModify.Replace("unicodePwd", []string{newpwdEncoded})
		// debugging crap
		// log.Printf("The stuff %s", *passwordModify)
		err = l.Modify(passwordModify)
		check(err)
		if err == nil {
			fmt.Printf("[+] Password change successful for user %s\n", detailstopass[0])
		}

	case flags.computers:
		fmt.Printf("[+] Searching for all computers in LDAP with baseDN %s\n", flags.basedn)
		filter := "(objectClass=computer)"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.constraineddelegation:
		fmt.Printf("[+] Searching for all Constrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectClass=User)(msDS-AllowedToDelegateTo=*))"
		attributes := []string{"samaccountname", "msDS-AllowedToDelegateTo"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.deleteobject != "":
		uorm, objectname, _ := strings.Cut(flags.deleteobject, " ")
		if uorm == "machine" {
			fmt.Printf("[+] Deleting machine account %s\n", uorm)
			delReq := ldap.NewDelRequest("CN="+objectname+",CN=Computers,"+flags.basedn, []ldap.Control{})
			err = l.Del(delReq)
			check(err)
			fmt.Printf("[+] Machine account %s deleted", uorm)
		} else if uorm == "user" {
			fmt.Printf("[+] Deleting user account %s\n", objectname)
			delReq := ldap.NewDelRequest("CN="+objectname+",CN=Users,"+flags.basedn, []ldap.Control{})
			err = l.Del(delReq)
			check(err)
			fmt.Printf("[+] User account %s deleted", objectname)
		} else {
			log.Fatal("[-] You have selected an invalid object type, exiting\n")
		}

	case flags.domaincontrollers:
		fmt.Printf("[+] Searching for all Domain Controllers in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.filter != "":
		fmt.Printf("[+] Searching with specified filter: %s in LDAP with baseDN %s\n", flags.filter, flags.basedn)
		filter := flags.filter
		attributes := []string{}
		ldapsearch(l, flags.basedn, flags.searchscope, filter, attributes)

	case flags.groups:
		fmt.Printf("[+] Searching for all groups in LDAP with baseDN %s\n", flags.basedn)
		filter := "(objectCategory=group)"
		attributes := []string{"sAMAccountName"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.groupswithmembers:
		fmt.Printf("[+] Searching for all groups and their members in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectCategory=group)(samaccountname=*)(member=*))"
		attributes := []string{"member"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.kerberoastable:
		fmt.Printf("[+] Searching for all Kerberoastable users in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectClass=User)(serviceprincipalname=*)(samaccountname=*))"
		attributes := []string{"samaccountname", "serviceprincipalname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.machineaccountquota:
		fmt.Printf("[+] Searching for ms-DS-MachineAccountQuota in LDAP with baseDN %s\n", flags.basedn)
		filter := "(objectClass=*)"
		attributes := []string{"ms-DS-MachineAccountQuota"}
		searchscope := 0
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.nopassword:
		fmt.Printf("[+] Searching for all users not required to have a password in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.objectquery != "":
		fmt.Printf("[+] Searching for attributes of object %s in LDAP with baseDN %s\n", flags.objectquery, flags.basedn)
		filter := "(&(objectClass=user)(samaccountname=" + flags.objectquery + "))"
		attributes := []string{}
		ldapsearch(l, flags.basedn, flags.searchscope, filter, attributes)

	case flags.passwordontexpire:
		fmt.Printf("[+] Searching for all users all objects where the password doesnt expire in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.passwordchangenextlogin:
		fmt.Printf("[+] Searching for all users all objects where the password is set to change at next login in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.protectedusers:
		fmt.Printf("[+] Searching for all users in Protected Users group in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(samaccountname=Protected Users)(member=*))"
		attributes := []string{"member"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.preauthdisabled:
		fmt.Printf("[+] Searching for all Kerberos Pre-auth Disabled users in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.querydescription != "":
		fmt.Printf("[+] Searching all objects for a description of %s in LDAP with baseDN %s\n", flags.querydescription, flags.basedn)
		filter := "(&(objectCategory=*)(description=" + flags.querydescription + "))"
		attributes := []string{"samaccountname", "description"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.rbcd:
		fmt.Printf("[+] Searching for all Resource Based Constrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
		filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
		attributes := []string{"samaccountname", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.schema:
		fmt.Printf("[+] Listing schema for LDAP database with baseDN %s\n", flags.basedn)
		filter := "(objectClass=*)"
		attributes := []string{}
		searchscope := 0
		ldapsearch(l, "cn=Schema,cn=Configuration,"+flags.basedn, searchscope, filter, attributes)

	case flags.shadowcredentials:
		fmt.Printf("[+] Searching for all Shadow Credentials in LDAP with baseDN %s\n", flags.basedn)
		filter := "(msDS-KeyCredentialLink=*)"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.unconstraineddelegation:
		fmt.Printf("[+] Searching for all Unconstrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
		filter := "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)

	case flags.users:
		fmt.Printf("[+] Searching for all users in LDAP with baseDN %s\n", flags.basedn)
		filter := "(&(objectCategory=person)(objectClass=user))"
		attributes := []string{"samaccountname"}
		searchscope := 2
		ldapsearch(l, flags.basedn, searchscope, filter, attributes)
	}
}
