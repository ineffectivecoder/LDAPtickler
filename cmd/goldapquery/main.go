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
	usage   string
}

var lookupTable map[string]action = map[string]action{
	// Todo add usages across the board
	"addmachine":                     {call: addmachine, numargs: 2, usage: "<machinename> <password>"},
	"addspn":                         {call: addspn, numargs: 2, usage: "<machinename> <spn>"},
	"adduser":                        {call: adduser, numargs: 3, usage: "<username> <principalname> <password>"},
	"certpublishers":                 {call: certpublishers, numargs: 0},
	"changepassword":                 {call: changepassword, numargs: 2, usage: "<username> <password>"},
	"computers":                      {call: computers, numargs: 0},
	"constraineddelegation":          {call: constraineddelegation, numargs: 0},
	"deleteobject":                   {call: deleteobject, numargs: 2, usage: "<objectname> <objecttype m or u>"},
	"disableconstraineddelegation":   {call: disablecd, numargs: 2, usage: "<samaccountname> <spnstoremove> or <all> to remove all"},
	"disablemachine":                 {call: disablemachine, numargs: 1, usage: "<machinename>"},
	"disablerbcd":                    {call: disablerbcd, numargs: 1, usage: "<samaccountname>"},
	"disablespn":                     {call: disablespn, numargs: 2, usage: "<samaccountname> <spnstoremove> or <all> to remove all"},
	"disableuser":                    {call: disableuser, numargs: 1, usage: "<username>"},
	"disableunconstraineddelegation": {call: disableud, numargs: 1, usage: "<samaccountname>"},
	"domaincontrollers":              {call: domaincontrollers, numargs: 0},
	"enablemachine":                  {call: enablemachine, numargs: 1, usage: "<machinename>"},
	"enableconstraineddelegation":    {call: enablecd, numargs: 2, usage: "<samaccountname> <spn>"},
	"enablerbcd":                     {call: enablerbcd, numargs: 2, usage: "<samaccountname> <delegatingcomputer>"},
	"enableuser":                     {call: enableuser, numargs: 1, usage: "<username>"},
	"enableunconstraineddelegation":  {call: enableud, numargs: 1, usage: "<samaccountname>"},
	"filter":                         {call: filter, numargs: 1, usage: "<filter>"},
	"groups":                         {call: groups, numargs: 0},
	"groupswithmembers":              {call: groupswithmembers, numargs: 0},
	"kerberoastable":                 {call: kerberoastable, numargs: 0},
	"machineaccountquota":            {call: machineaccountquota, numargs: 0},
	"nopassword":                     {call: nopassword, numargs: 0},
	"objectquery":                    {call: objectquery, numargs: 1, usage: "<objectname>"},
	"passworddontexpire":             {call: passworddontexpire, numargs: 0},
	"passwordchangenextlogin":        {call: passwordchangenextlogin, numargs: 0},
	"protectedusers":                 {call: protectedusers, numargs: 0},
	"preauthdisabled":                {call: preauthdisabled, numargs: 0},
	"querydescription":               {call: querydescription, numargs: 1, usage: "<description>"},
	"rbcd":                           {call: rbcd, numargs: 0},
	"schema":                         {call: schema, numargs: 0},
	"shadowcredentials":              {call: shadowcredentials, numargs: 0},
	"unconstraineddelegation":        {call: unconstraineddelegation, numargs: 0},
	"users":                          {call: users, numargs: 0},
	"whoami":                         {call: whoami, numargs: 0},
}

// Global state
var state struct {
	mode     goldapquery.BindMethod
	password string
}

// Flags
var flags struct {
	attributes        cli.StringList
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

	cli.Section("Supported Utility Commands", "addmachine, addspn, adduser, changepassword, deleteobject,",
		"disablemachine,disableconstraineddelegation, disableunconstraineddelegation, disableuser, enableconstraineddelegation, enablemachine, enableunconstraineddelegation enableuser")

	// cli.SectionAligned("Supported Utility Commands", "::", "addmachine <machinename> <machinepass>::Adds a new machine to the domain") //TODO ADD THE REST

	cli.Section("Supported LDAP Queries", "certpublishers, computers, constraineddelegation, domaincontrollers,",
		"groups, groupswithmembers, kerberoastable, machineaccountquota, nopassword, objectquery,",
		"passworddontexpire, passwordchangenextlogin, protectedusers, preauthdisabled, querydescription,",
		"rbcd, schema, shadowcredentials, unconstraineddelegation, users, whoami",
	)
	// Parse cli flags
	cli.Flag(&flags.attributes, "a", "attributes", "Specify attributes for LDAPSearch, ex samaccountname,serviceprincipalname. Usage of this may break things")
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
			log.Fatalf("Usage: goldapquery %s %s", cli.Arg(0), act.usage)
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

func main() {
	var c *goldapquery.Conn = goldapquery.New(flags.ldapURL, flags.basedn, flags.skipVerify)
	var err error

	// Attempt anonymous bind, check for flag
	switch state.mode {
	case goldapquery.MethodBindAnonymous:
		fmt.Printf("[+] Attempting anonymous bind to %s\n", flags.ldapURL)
		err = c.BindAnonymous(flags.username)

	case goldapquery.MethodBindDomain:
		fmt.Printf("[+] Attempting NTLM bind to %s\n", flags.ldapURL)
		err = c.BindDomain(flags.domain, flags.username, state.password)

	case goldapquery.MethodBindDomainPTH:
		fmt.Printf("[+] Attempting NTLM Pass The Hash bind to %s\n", flags.ldapURL)
		err = c.BindDomainPTH(flags.domain, flags.username, flags.pth)

	case goldapquery.MethodBindPassword:
		fmt.Printf("[+] Attempting bind with credentials to %s\n", flags.ldapURL)
		err = c.BindPassword(flags.username, state.password)

		/*case bindGSSAPI:
		fmt.Printf("[+] Attempting GSSAPI bind to %s\n", flags.ldapURL)
		err = l.GSSAPIBindRequest(gssClient)
		check(err)
		fmt.Println("[+] GSSAPI bind successful")*/
	}
	check(err)
	defer c.Close()
	fmt.Printf("[+] Successfully connected to %s\n", flags.ldapURL)
	err = lookupTable[strings.ToLower(cli.Arg(0))].call(c, cli.Args()[1:]...)
	check(err)
	if err == nil {
		os.Exit(0)
	}
}

func addmachine(c *goldapquery.Conn, args ...string) error {
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

func addspn(c *goldapquery.Conn, args ...string) error {
	machinename := args[0]
	spn := args[1]
	fmt.Printf("[+] Adding spn %s to machine account %s\n", spn, machinename)
	err := c.AddServicePrincipalName(machinename, spn)
	check(err)
	fmt.Printf("[+] Successfully added spn %s to machine account %s\n", spn, machinename)
	return nil
}

func adduser(c *goldapquery.Conn, args ...string) error {
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
	objectname := cli.Arg(1)
	err := c.SetDisableMachineAccount(objectname)
	check(err)
	fmt.Printf("[+] Machine account %s disabled\n", objectname)
	return nil
}

func disablecd(c *goldapquery.Conn, args ...string) error {
	samaccountname := args[0]
	spn := args[1]
	fmt.Printf("[+] Removing constrained delegation spn %s from %s \n", spn, samaccountname)
	err := c.RemoveConstrainedDelegation(samaccountname, spn)
	check(err)
	return nil
}

func disablerbcd(c *goldapquery.Conn, args ...string) error {
	samaccountname := args[0]
	fmt.Printf("[+] Removing RBCD from %s\n", samaccountname)
	err := c.RemoveResourceBasedConstrainedDelegation(samaccountname)
	check(err)
	return nil
}

func disableud(c *goldapquery.Conn, args ...string) error {
	samaccountname := args[0]
	fmt.Printf("[+] Removing unconstrained delegation from %s\n", samaccountname)
	err := c.RemoveUnconstrainedDelegation(samaccountname)
	check(err)
	return nil
}

func disablespn(c *goldapquery.Conn, args ...string) error {
	samaccountname := args[0]
	spn := args[1]
	if strings.ToLower(spn) == "all" {
		fmt.Printf("[+] Removing all service principal names from %s\n", samaccountname)
		err := c.RemoveSPNs(samaccountname, spn)
		check(err)
	} else {
		fmt.Printf("[+] Removing service principal name %s from %s\n", spn, samaccountname)
		err := c.RemoveSPNs(samaccountname, spn)
		check(err)
	}
	return nil
}

func disableuser(c *goldapquery.Conn, args ...string) error {
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
	objectname := cli.Arg(1)
	err := c.SetEnableMachineAccount(objectname)
	check(err)
	fmt.Printf("[+] Machine account %s enabled\n", objectname)
	return nil
}

func enablecd(c *goldapquery.Conn, args ...string) error {
	samaccountname := args[0]
	spn := args[1]
	fmt.Printf("[+] Adding constrained delegation spn %s to %s\n", spn, samaccountname)
	err := c.AddConstrainedDelegation(samaccountname, spn)
	check(err)
	return nil
}

func enableud(c *goldapquery.Conn, args ...string) error {
	samaccountname := args[0]
	fmt.Printf("[+] Adding unconstrained delegation to %s\n", samaccountname)
	err := c.AddUnconstrainedDelegation(samaccountname)
	check(err)
	return nil
}

func enablerbcd(c *goldapquery.Conn, args ...string) error {
	samaccountname := args[0]
	delegatingcomputer := args[1]
	fmt.Printf("[+] Adding RBCD to %s setting delegation for %s\n", samaccountname, delegatingcomputer)
	err := c.AddResourceBasedConstrainedDelegation(samaccountname, delegatingcomputer)
	check(err)
	return nil
}

func enableuser(c *goldapquery.Conn, args ...string) error {
	objectname := cli.Arg(1)
	err := c.SetEnableUserAccount(objectname)
	check(err)
	fmt.Printf("[+] User account %s enabled\n", objectname)
	return nil
}

func expandlist(in []string) []string {
	var out []string
	for _, s := range in {
		out = append(out, strings.Split(s, ",")...)
	}
	return out
}

func filter(c *goldapquery.Conn, args ...string) error {
	filter := cli.Arg(1)
	fmt.Printf("[+] Searching with specified filter: %s in LDAP with baseDN %s\n", filter, flags.basedn)
	err := c.LDAPSearch(flags.searchscope, filter, expandlist(flags.attributes))
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
	err := c.ListUsers(expandlist(flags.attributes)...)
	check(err)
	return nil
}

func whoami(c *goldapquery.Conn, args ...string) error {
	fmt.Printf("[+] Querying the LDAP server for WhoAmI with baseDN %s\n", flags.basedn)
	result, err := c.GetWhoAmI()
	check(err)
	fmt.Printf("[+] You are currently authenticated as %+v\n", *result)
	return nil
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
