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
type action struct {
	call    func(*goldapquery.Conn, ...string) error
	numargs int
}

var lookupTable map[string]action = map[string]action{
	"addmachine":              {call: addmachine, numargs: 2},
	"adduser":                 {call: adduser, numargs: 3},
	"certpublishers":          {call: certpublishers, numargs: 0},
	"changepassword":          {call: changepassword, numargs: 2},
	"computers":               {call: computers, numargs: 0},
	"constraineddelegation":   {call: constraineddelegation, numargs: 0},
	"deleteobject":            {call: deleteobject, numargs: 2},
	"disablemachine":          {call: disablemachine, numargs: 1},
	"disableuser":             {call: disableuser, numargs: 1},
	"domaincontrollers":       {call: domaincontrollers, numargs: 0},
	"enablemachine":           {call: enablemachine, numargs: 1},
	"enableuser":              {call: enableuser, numargs: 1},
	"filter":                  {call: filter, numargs: 1},
	"groups":                  {call: groups, numargs: 0},
	"groupswithmembers":       {call: groupswithmembers, numargs: 0},
	"kerberoastable":          {call: kerberoastable, numargs: 0},
	"machineaccountquota":     {call: machineaccountquota, numargs: 0},
	"nopassword":              {call: nopassword, numargs: 0},
	"objectquery":             {call: objectquery, numargs: 1},
	"passworddontexpire":      {call: passworddontexpire, numargs: 0},
	"passwordchangenextlogin": {call: passwordchangenextlogin, numargs: 0},
	"protectedusers":          {call: protectedusers, numargs: 0},
	"preauthdisabled":         {call: preauthdisabled, numargs: 0},
	"querydescription":        {call: querydescription, numargs: 1},
	"rbcd":                    {call: rbcd, numargs: 0},
	"schema":                  {call: schema, numargs: 0},
	"shadowcredentials":       {call: shadowcredentials, numargs: 0},
	"unconstraineddelegation": {call: unconstraineddelegation, numargs: 0},
	"users":                   {call: users, numargs: 0},
	"whoami":                  {call: whoami, numargs: 0},
}

// Global state
var state struct {
	mode     goldapquery.BindMethod
	password string
}

// Flags
var flags struct {
	attributes        string
	basedn            string
	domain            string
	domaincontrollers bool
	filter            string
	gssapi            bool
	ldapURL           string
	password          bool
	pth               string
	searchscope       int
	skipVerify        bool
	username          string
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

	cli.Section("Supported Utility Commands", "addmachine, adduser, changepassword, deleteobject,",
		"disablemachine, disableuser, enablemachine, enableuser")

	// cli.SectionAligned("Supported Utility Commands", "::", "addmachine <machinename> <machinepass>::Adds a new machine to the domain") //TODO ADD THE REST

	cli.Section("Supported LDAP Queries", "certpublishers, computers, constraineddelegation, domaincontrollers,",
		"groups, groupswithmembers, kerberoastable, machineaccountquota, nopassword, objectquery,",
		"passworddontexpire, passwordchangenextlogin, protectedusers, preauthdisabled, querydescription,",
		"rbcd, schema, shadowcredentials, unconstraineddelegation, users, whoami",
	)
	// Parse cli flags
	cli.Flag(&flags.attributes, "a", "attributes", "", "Specify attributes for LDAPSearch, ex samaccountname,serviceprincipalname")
	cli.Flag(&flags.filter, "f", "filter", "", "Specify your own filter. ex. (objectClass=computer)")
	cli.Flag(&flags.gssapi, "gssapi", false, "Enable GSSAPI and attempt to authenticate")
	cli.Flag(&flags.domain, "d", "domain", "", "Domain for NTLM bind")
	cli.Flag(&flags.basedn, "b", "basedn", "", "Specify baseDN for query, ex. ad.sostup.id would be dc=ad,dc=sostup,dc=id")
	cli.Flag(&flags.ldapURL, "l", "ldapurl", "", "LDAP(S) URL to connect to")
	cli.Flag(&flags.password, "p", "password", false, "Password to bind with, will prompt")
	cli.Flag(&flags.username, "u", "user", "", "Username to bind with")
	cli.Flag(&flags.skipVerify, "s", "skip", false, "Skip SSL verification")
	cli.Flag(&flags.searchscope, "scope", 2, "Define scope of search, 0=Base, 1=Single Level, 2=Whole Sub Tree, 3=Children, only used by filter and objectquery")
	cli.Flag(&flags.pth, "pth", "", "Bind with password hash, WHY IS THIS SUPPORTED OTB?!")
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

	cli.Parse()

	// Check for ldapURL, because wtf are we going to connect to without it
	if flags.ldapURL == "" {
		cli.Usage(1)
	}

	// Ensure we are passing no arguments. There shouldn't be any. Only parameters.
	if cli.NArg() < 1 {
		cli.Usage(1)
	}

	if act, ok := lookupTable[strings.ToLower(cli.Arg(0))]; !ok {
		log.Fatal("[-] Invalid command")
	} else {
		if act.numargs != cli.NArg()-1 {
			log.Fatalf("received %d args, expected %d\n", cli.NArg()-1, act.numargs)
		}
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

func addmachine(c *goldapquery.Conn, args ...string) error {
	if len(args) != 2 {
		return fmt.Errorf("expected machinename, and password")
	}
	machinename := args[0]
	machinepass := args[1]
	// machinename, machinepass, _ := strings.Cut(flags.addmachine, " ")
	err := c.AddMachineAccount(machinename, machinepass)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Added machine account %s successfully with password %s\n", machinename, machinepass)
	return nil
}

func adduser(c *goldapquery.Conn, args ...string) error {
	if len(args) != 3 {
		return fmt.Errorf("expected username, serviceprincipal and password")
	}

	username := args[0]
	principalname := args[1]
	userpasswd := args[2]
	fmt.Printf("[+] Adding username %s with serviceprincipal %s with password %s\n", username, principalname, userpasswd)
	err := c.AddUserAccount(username, principalname)
	check(err)
	fmt.Printf("[+] Successfully added user account %s\n", username)
	fmt.Printf("[+] Now setting password...\n")
	err = c.SetUserPassword(username, userpasswd)
	check(err)
	fmt.Printf("[+] Password set successfully for user %s\n", username)
	fmt.Printf("[+] Now enabling account for user %s\n", username)
	err = c.SetEnableUserAccount(username)
	check(err)
	fmt.Printf("[+] Successfully added and enabled user account %s\n", username)
	return nil
}

func certpublishers(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Certificate Publishers in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListCAs()
	check(err)
	return nil
}

func changepassword(c *goldapquery.Conn, args ...string) error {
	if len(args) != 2 {
		return fmt.Errorf("expected username, password")
	}
	username := args[0]
	userpasswd := args[1]

	fmt.Printf("[+] Changing password for user %s with password supplied in LDAP with baseDN %s\n", username, flags.basedn)
	err := c.SetUserPassword(username, userpasswd)
	check(err)
	fmt.Printf("[+] Password change successful for user %s\n", username)
	return nil
}

func computers(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all computers in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListComputers()
	check(err)
	return nil
}

func constraineddelegation(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Constrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListConstrainedDelegation()
	check(err)
	return nil
}

func deleteobject(c *goldapquery.Conn, args ...string) error {
	if len(args) != 2 {
		return fmt.Errorf("expected objectname and type m or u for machine or user")
	}
	objectname := cli.Arg(1)
	objecttype := cli.Arg(2)
	if objecttype == "m" {
		fmt.Printf("[+] Deleting machine account %s\n", objectname)
		err := c.DeleteObject(objectname, objecttype)
		check(err)
		fmt.Printf("[+] Machine account %s deleted\n", objectname)
	} else {
		fmt.Printf("[+] Deleting user account %s\n", objectname)
		err := c.DeleteObject(objectname, objecttype)
		check(err)
		fmt.Printf("[+] User account %s deleted\n", objectname)
	}
	return nil
}

func disablemachine(c *goldapquery.Conn, args ...string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected machinename")
	}
	objectname := cli.Arg(1)
	err := c.SetDisableMachineAccount(objectname)
	check(err)
	fmt.Printf("[+] Machine account %s disabled\n", objectname)
	return nil
}

func disableuser(c *goldapquery.Conn, args ...string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected username")
	}
	objectname := cli.Arg(1)
	err := c.SetDisableUserAccount(objectname)
	check(err)
	fmt.Printf("[+] User account %s disabled\n", objectname)
	return nil
}

func domaincontrollers(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Domain Controllers in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListDCs()
	check(err)
	return nil
}

func enablemachine(c *goldapquery.Conn, args ...string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected machinename")
	}
	objectname := cli.Arg(1)
	err := c.SetEnableMachineAccount(objectname)
	check(err)
	fmt.Printf("[+] Machine account %s enabled\n", objectname)
	return nil
}

func enableuser(c *goldapquery.Conn, args ...string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected username")
	}
	objectname := cli.Arg(1)
	err := c.SetEnableUserAccount(objectname)
	check(err)
	fmt.Printf("[+] User account %s enabled\n", objectname)
	return nil
}

func filter(c *goldapquery.Conn, args ...string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected filter for example (objectCategory=group). May also accept attributes and searchscope")
	}
	filter := cli.Arg(1)
	fmt.Printf("[+] Searching with specified filter: %s in LDAP with baseDN %s\n", filter, flags.basedn)
	err := c.LDAPSearch(flags.searchscope, filter, strings.Split(flags.attributes, ","))
	check(err)
	return nil
}

func groups(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all groups in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListGroups()
	check(err)
	return nil
}

func groupswithmembers(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all groups and their members in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListGroupswithMembers()
	check(err)
	return nil
}

func kerberoastable(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Kerberoastable users in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListKerberoastable()
	check(err)
	return nil
}

func machineaccountquota(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for ms-DS-MachineAccountQuota in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListMachineAccountQuota()
	check(err)
	return nil
}

func nopassword(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users not required to have a password in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListNoPassword()
	check(err)
	return nil
}

func objectquery(c *goldapquery.Conn, args ...string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected objectname)")
	}
	objectname := cli.Arg(1)
	fmt.Printf("[+] Searching for attributes of object %s in LDAP with baseDN %s\n", objectname, flags.basedn)
	err := c.FindUserByName(objectname, flags.searchscope)
	check(err)
	return nil
}

func passworddontexpire(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users all objects where the password doesn't expire in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListPasswordDontExpire()
	check(err)
	return nil
}

func passwordchangenextlogin(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users all objects where the password is set to change at next login in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListPasswordChangeNextLogin()
	check(err)
	return nil
}

func protectedusers(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users in Protected Users group in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListProtectedUsers()
	check(err)
	return nil
}

func preauthdisabled(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Kerberos Pre-auth Disabled users in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListPreAuthDisabled()
	check(err)
	return nil
}

func querydescription(c *goldapquery.Conn, args ...string) error {

	if len(args) != 1 {
		log.Fatal("[-] Expected specific description to search for\n")
	}
	querydescription := cli.Arg(1)
	fmt.Printf("[+] Searching all objects for a description of %s in LDAP with baseDN %s\n", querydescription, flags.basedn)
	err := c.FindUserByDescription(querydescription)
	check(err)
	return nil
}

func rbcd(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Resource Based Constrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListRBCD()
	check(err)
	return nil
}

func schema(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Listing schema for LDAP database with baseDN %s\n", flags.basedn)
	err := c.ListSchema()
	check(err)
	return nil
}

func shadowcredentials(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Shadow Credentials in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListShadowCredentials()
	check(err)
	return nil
}

func unconstraineddelegation(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Unconstrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListUnconstrainedDelegation()
	check(err)
	return nil
}

func users(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListUsers()
	check(err)
	return nil
}

func whoami(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Querying the LDAP server for WhoAmI with baseDN %s\n", flags.basedn)
	result, err := c.GetWhoAmI()
	check(err)
	fmt.Printf("[+] You are currently authenticated as %s", result)
	return nil
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
	// f = function pointer

	err = lookupTable[strings.ToLower(cli.Arg(0))].call(c, cli.Args()[1:]...)
	check(err)
	if err == nil {
		os.Exit(0)
	}

}

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
