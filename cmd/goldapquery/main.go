package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	//"github.com/jcmturner/gokrb5/v8/client"
	"git.red.team/silversurfer/goldapquery"

	//"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/mjwhitta/cli"
	"golang.org/x/term"
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
	attributes              string
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
		log.Fatalf("[-] %s\n", err)
	}
}

func init() {
	var bytepw []byte
	var err error
	log.Default().SetFlags(0)
	// Configure cli package
	cli.Align = true // Defaults to false
	cli.Authors = []string{"Chris Hodson r2d2@sostup.id"}
	cli.Banner = fmt.Sprintf("%s [OPTIONS] <arg>", os.Args[0])
	cli.Info("A tool to simplify LDAP queries because it sucks and is not fun")

	// Parse cli flags
	cli.Flag(&flags.domain, "d", "domain", "", "Domain for NTLM bind")
	cli.Flag(&flags.basedn, "b", "basedn", "", "Specify baseDN for query, ex. ad.sostup.id would be dc=ad,dc=sostup,dc=id")
	cli.Flag(&flags.ldapURL, "l", "ldapurl", "", "LDAP(S) URL to connect to")
	cli.Flag(&flags.password, "p", "password", false, "Password to bind with, will prompt")
	cli.Flag(&flags.username, "u", "user", "", "Username to bind with")
	cli.Flag(&flags.skipVerify, "s", "skip", false, "Skip SSL verification")
	cli.Flag(&flags.searchscope, "scope", 2, "Define scope of search, 0=Base, 1=Single Level, 2=Whole Sub Tree, 3=Children, only used by filter and objectquery")
	cli.Flag(&flags.pth, "pth", "", "Bind with password hash, WHY IS THIS SUPPORTED OTB?!")
	cli.Flag(&flags.gssapi, "gssapi", false, "Enable GSSAPI and attempt to authenticate")

	/*
	cli.Flag(&flags.addmachine, "addmachine", "", "Add Machine account, ex computername$ password")
	cli.Flag(&flags.addmachinelowpriv, "lpaddmachine", "", "Add machine account with low priv user. ex computername$ password")
	cli.Flag(&flags.adduser, "adduser", "", "Add a user, ex username username@domain password")
	cli.Flag(&flags.certpublishers, "cert", false, "Search for all CAs in the environment")
	cli.Flag(&flags.changepassword, "cp", "", "Change password for user, must use LDAPS you will need permissions so no funny business. ex. username newpassword")
	cli.Flag(&flags.computers, "computers", false, "Search for all Computer objects")
	cli.Flag(&flags.constraineddelegation, "cd", false, "Search for all objects configured for Constrained Delegation")
	cli.Flag(&flags.deleteobject, "do", "", "Delete an object in AD, initial support for machine accounts and users, ex. machine/user objectname")
	cli.Flag(&flags.domaincontrollers, "dc", false, "Search for all Domain Controllers")
	cli.Flag(&flags.groups, "groups", false, "Search for all group objects")
	cli.Flag(&flags.groupswithmembers, "groupmembers", false, "Search for all groups and their members")
	cli.Flag(&flags.kerberoastable, "kerberoastable", false, "Search for kerberoastable users")
	cli.Flag(&flags.machineaccountquota, "maq", false, "Retrieve the attribute ms-DS-MachineAccount Quota to determine how many machine accounts a user may create")
	cli.Flag(&flags.nopassword, "np", false, "Search for users not required to have a password")
	cli.Flag(&flags.objectquery, "oq", "", "Provide all attributes of specific user/computer object, machine accounts will need trailing $")
	cli.Flag(&flags.passwordontexpire, "pde", false, "Search for objects where the password doesn't expire")
	cli.Flag(&flags.passwordchangenextlogin, "pcnl", false, "Search for objects where the password is required to be changed at next login")
	cli.Flag(&flags.protectedusers, "pu", false, "Search for users in Protected Users group")
	cli.Flag(&flags.preauthdisabled, "pad", false, "Search for users with Kerberos Pre-auth Disabled")
	cli.Flag(&flags.querydescription, "qd", "", "Query all objects for a specific description, useful for finding data like creds in description fields")
	cli.Flag(&flags.rbcd, "rbcd", false, "Search for  all objects configured with Resource Based Constrained Delegation")
	cli.Flag(&flags.schema, "schema", false, "Dump the schema of the LDAP database")
	cli.Flag(&flags.shadowcredentials, "sc", false, "Search for all objects with Shadow Credentials")
	cli.Flag(&flags.unconstraineddelegation, "ud", false, "Search for all objects configured for Unconstrained Delegation")
	cli.Flag(&flags.users, "users", false, "Search for all User objects")
*/
	cli.Flag(&flags.attributes, "attributes", "", "Specify attributes for LDAPSearch, ex samaccountname,serviceprincipalname")
	cli.Flag(&flags.filter, "f", "filter", "", "Specify your own filter. ex. (objectClass=computer)")

	cli.Parse()

	// Check for ldapURL, because wtf are we going to connect to without it
	if flags.ldapURL == "" {
		cli.Usage(1)
	}

	// Ensure we are passing no arguments. There shouldn't be any. Only parameters.
	if cli.NArg() < 1 {
		cli.Usage(1)
	}

	/* Various checks for flag combinations that don't make sense.
	Allowing a username for anonymous binds since the spec for LDAP allows it for tracking purposes.
	Reading password using term.ReadPassword to prevent echoing of the credential or needing it in plain text.

	*/

	if flags.password && flags.pth != "" {
		log.Fatal("[-] Silly Goose detected, you can't PTH and provide a password")
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
	// Broken GSSAPI crap
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

func main() {
	var c *goldapquery.Conn
	var err error
	goldapquery.SkipVerify = flags.skipVerify
	goldapquery.BaseDN = flags.basedn

	// Attempt anonymous bind, check for flag
	switch state.mode {
	case goldapquery.MethodBindAnonymous:
		fmt.Printf("[+] Attempting anonymous bind to %s\n", flags.ldapURL)
		c, err = goldapquery.BindAnonymous(flags.ldapURL, flags.username)

	case goldapquery.MethodBindPassword:
		fmt.Printf("[+] Attempting bind with credentials to %s\n", flags.ldapURL)
		c, err = goldapquery.BindPassword(flags.ldapURL, flags.username, state.password)

	case goldapquery.MethodBindDomain:
		fmt.Printf("[+] Attempting NTLM bind to %s\n", flags.ldapURL)
		c, err = goldapquery.BindDomain(flags.ldapURL, flags.domain, flags.username, state.password)

	case goldapquery.MethodBindDomainPTH:
		fmt.Printf("[+] Attempting NTLM Pass The Hash bind to %s\n", flags.ldapURL)
		c, err = goldapquery.BindDomainPTH(flags.ldapURL, flags.domain, flags.username, flags.pth)

		/*case bindGSSAPI:
		fmt.Printf("[+] Attempting GSSAPI bind to %s\n", flags.ldapURL)
		err = l.GSSAPIBindRequest(gssClient)
		check(err)
		fmt.Println("[+] GSSAPI bind successful")*/
	}
	check(err)
	defer c.Close()
	fmt.Printf("[+] Successfully connected to %s\n", flags.ldapURL)

	// We have so much power here with the filters. Basically any filter that works in ldapsearch should work here.
	// In order to simplify searching for various objects, we will have a reasonable number of flags for things like:
	// computers, users, kerberoastable users. We will also accommodate users who are comfy using their own filter.
	switch strings.ToLower(cli.Arg(0)) {

		case "addmachine":
		if cli.NArg() != 3 {
			log.Fatal("[-] Expected machinename, and password\n")
		}
		machinename := cli.Arg(1)
		machinepass := cli.Arg(2)
		//machinename, machinepass, _ := strings.Cut(flags.addmachine, " ")
		err = c.AddMachineAccount(machinename, machinepass)
		check(err)
		fmt.Printf("[+] Added machine account %s successfully with password %s\n", cli.Arg(1), cli.Arg(2))

		//Completely broken pending research into GSSAPI, connection is not secure enough for low priv user to do this :(
		/*case flags.addmachinelowpriv != "":
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
		fmt.Printf("[+] Added machine account %s with a low priv account successfully with password %s\n", machinename, machinepass)*/

		case "adduser":
		if cli.NArg() != 4 {
			log.Fatal("[-] Expected username, principalname and password\n")
		}
			
		username := cli.Arg(1)
		principalname := cli.Arg(2)
		userpasswd := cli.Arg(3)
		fmt.Printf("[+] Adding username %s with serviceprincipal %s with password %s\n", username, principalname, userpasswd)
		err := c.AddUserAccount(username, principalname)
		check(err)
		fmt.Printf("[+] Successfully added user account %s\n", username)
		fmt.Printf("[+] Now setting password...\n")
		err = c.SetUserPassword(username, userpasswd)
		check(err)
		fmt.Printf("[+] Password set successfully for user %s\n", username)
		fmt.Printf("[+] Now enabling account for user %s\n", username)
		err = c.SetEnableAccount(username)
		check(err)
		fmt.Printf("[+] Successfully added and enabled user account %s\n", username)

		case "certpublishers":
		fmt.Printf("[+] Searching for all Certificate Publishers in LDAP with baseDN %s\n", flags.basedn)
		err = c.ListCAs()

		case "changepassword":
			if cli.NArg() != 3 {
			log.Fatal("[-] Expected username and password\n")
		}
			username := cli.Arg(1)
			userpasswd := cli.Arg(2)
			
			fmt.Printf("[+] Changing password for user %s with password supplied in LDAP with baseDN %s\n", username, flags.basedn)
			err = c.SetUserPassword(username, userpasswd)
			check(err)
			fmt.Printf("[+] Password change successful for user %s\n", username)

		case "computers":
			fmt.Printf("[+] Searching for all computers in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListComputers()

		case "constraineddelegation":
			fmt.Printf("[+] Searching for all Constrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListConstrainedDelegation()

		case "deleteobject":
			if cli.NArg() != 2 {
			log.Fatal("[-] Expected machinename or username\n")
		}
			objectname := cli.Arg(1)
			if strings.HasSuffix(objectname, "$") {
				fmt.Printf("[+] Deleting machine account %s\n", objectname)
				err = c.DeleteObject(objectname)
				check(err)
				fmt.Printf("[+] Machine account %s deleted\n", objectname)
			} else {
				fmt.Printf("[+] Deleting user account %s\n", objectname)
				err = c.DeleteObject(objectname)
				check(err)
				fmt.Printf("[+] User account %s deleted\n", objectname)
			}

		case "domaincontrollers":
			fmt.Printf("[+] Searching for all Domain Controllers in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListDCs()

		case "filter":
			if cli.NArg() != 2 {
			log.Fatal("[-] Expected filter for example (objectCategory=group). May also accept attributes and searchscope\n")
		}
			filter := cli.Arg(1)
			fmt.Printf("[+] Searching with specified filter: %s in LDAP with baseDN %s\n", filter, flags.basedn)
			err = c.LDAPSearch(flags.searchscope, filter, strings.Split(flags.attributes, ","))

		case "groups":
			fmt.Printf("[+] Searching for all groups in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListGroups()

		case "groupswithmembers":
			fmt.Printf("[+] Searching for all groups and their members in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListGroupswithMembers()

		case "kerberoastable":
			fmt.Printf("[+] Searching for all Kerberoastable users in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListKerberoastable()

		case "machineaccountquota":
			fmt.Printf("[+] Searching for ms-DS-MachineAccountQuota in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListMachineAccountQuota()

		case "nopassword":
			fmt.Printf("[+] Searching for all users not required to have a password in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListNoPassword()

		case "objectquery":
			if cli.NArg() != 2 {
			log.Fatal("[-] Expected specific objectname\n")
		}
		    objectname := cli.Arg(1)
			fmt.Printf("[+] Searching for attributes of object %s in LDAP with baseDN %s\n", objectname, flags.basedn)
			err = c.FindUserByName(objectname, flags.searchscope)

		case "passworddontexpire":
			fmt.Printf("[+] Searching for all users all objects where the password doesn't expire in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListPasswordDontExpire()

		case "passwordchangenextlogin":
			fmt.Printf("[+] Searching for all users all objects where the password is set to change at next login in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListPasswordChangeNextLogin()

		case "protectedusers":
			fmt.Printf("[+] Searching for all users in Protected Users group in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListProtectedUsers()

		case "preauthdisabled":
			fmt.Printf("[+] Searching for all Kerberos Pre-auth Disabled users in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListPreAuthDisabled()

		case "querydescription":
			if cli.NArg() != 2 {
			log.Fatal("[-] Expected specific description to search for\n")
		}
		    querydescription := cli.Arg(1)
			fmt.Printf("[+] Searching all objects for a description of %s in LDAP with baseDN %s\n", querydescription, flags.basedn)
			err = c.FindUserByDescription(querydescription)

		case "rbcd":
			fmt.Printf("[+] Searching for all Resource Based Constrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListRBCD()

		case "schema":
			fmt.Printf("[+] Listing schema for LDAP database with baseDN %s\n", flags.basedn)
			err = c.ListSchema()

		case "shadowcredentials":
			fmt.Printf("[+] Searching for all Shadow Credentials in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListShadowCredentials()

		case "unconstraineddelegation":
			fmt.Printf("[+] Searching for all Unconstrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListUnconstrainedDelegation()

		case "users":
			fmt.Printf("[+] Searching for all users in LDAP with baseDN %s\n", flags.basedn)
			err = c.ListUsers()
			
	}
	check(err)
}
