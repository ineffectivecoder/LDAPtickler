package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	ldaptickler "github.com/ineffectivecoder/LDAPtickler"
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
	call    func(*ldaptickler.Conn, ...string) error
	numargs int
	usage   string
}

var lookupTable map[string]action = map[string]action{
	// Todo add usages across the board
	"addmachine":                     {call: addmachine, numargs: 2, usage: "<machinename> <password>"},
	"addmachinelp":                   {call: addmachinelp, numargs: 3, usage: "<machinename> <password> <domain>"},
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
	"dnsrecords":                     {call: dnsrecords, numargs: 0},
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
	"machinecreationdacl":            {call: machinecreationdacl, numargs: 0},
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
	mode     ldaptickler.BindMethod
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
	insecure          bool
	dc                string
	password          bool
	passwordcli       string
	pth               string
	searchscope       int
	skipVerify        bool
	username          string
	verbose           bool
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

	cli.SectionAligned("Supported Utility Commands", "::",
		"addmachine <machinename> <machinepass>::Adds a new machine to the domain\n",
		"addmachinelp <machinename> <machinepass>::Adds a new machine using low-priv credentials\n",
		"addspn <accountname> <spn>::Adds an SPN to an account\n",
		"adduser <username> <password>::Creates a new user\n",
		"changepassword <accountname> <newpassword>::Changes the password for an account\n",
		"deleteobject <objectname>::Deletes an object from the directory\n",
		"disablemachine <machinename>::Disables a machine account\n",
		"disableconstraineddelegation <accountname>::Disables constrained delegation for an account\n",
		"disablespn <accountname> <spn>::Removes an SPN from an account\n",
		"disableunconstraineddelegation <accountname>::Disables unconstrained delegation for an account\n",
		"disableuser <username>::Disables a user account\n",
		"enableconstraineddelegation <accountname> <service>::Enables constrained delegation for an account\n",
		"enablemachine <machinename>::Enables a machine account\n",
		"enablespn <accountname> <spn>::Adds an SPN to an account\n",
		"enableunconstraineddelegation <accountname>::Enables unconstrained delegation for an account\n",
		"enableuser <username>::Enables a user account\n",
	)

	cli.SectionAligned("Supported LDAP Queries", "::",
		"certpublishers::Returns all Certificate Publishers in the domain\n",
		"computers::Lists all computer objects in the domain\n",
		"constraineddelegation::Lists accounts configured for constrained delegation\n",
		"dnsrecords::Returns DNS records stored in Active Directory\n",
		"domaincontrollers::Lists all domain controllers in the domain\n",
		"groups::Lists all security and distribution groups\n",
		"groupswithmembers::Lists groups and their associated members\n",
		"kerberoastable::Finds accounts vulnerable to Kerberoasting\n",
		"machineaccountquota::Displays the domain's MachineAccountQuota setting\n",
		"machinecreationdacl::Displays the domain's Machine Creation DACL\n",
		"nopassword::Lists accounts with empty or missing passwords\n",
		"objectquery::Performs a raw LDAP object query\n",
		"passworddontexpire::Lists accounts with 'Password Never Expires' set\n",
		"passwordchangenextlogin::Lists accounts that must change password at next login\n",
		"protectedusers::Lists members of the Protected Users group\n",
		"preauthdisabled::Lists accounts with Kerberos pre-authentication disabled\n",
		"querydescription::Displays descriptions\n",
		"rbcd::Lists accounts configured for Resource-Based Constrained Delegation (RBCD)\n",
		"schema::Lists schema objects or extended attributes\n",
		"shadowcredentials::Lists users with shadow (msDS-KeyCredential) credentials\n",
		"unconstraineddelegation::Lists accounts with unconstrained delegation enabled\n",
		"users::Lists all user accounts in the domain\n",
		"whoami::Runs a whoami-style LDAP query for the current user\n",
	)

	// Parse cli flags
	cli.Flag(&flags.attributes, "a", "attributes", "Specify attributes for LDAPSearch, ex samaccountname,serviceprincipalname. Usage of this may break things")
	cli.Flag(&flags.filter, "f", "filter", "", "Specify your own filter. ex. (objectClass=computer)")
	cli.Flag(&flags.gssapi, "g", "gssapi", false, "Enable GSSAPI and attempt to authenticate")
	cli.Flag(&flags.domain, "d", "domain", "", "Domain for NTLM bind")
	cli.Flag(&flags.basedn, "b", "basedn", "", "Specify baseDN for query, ex. ad.sostup.id would be dc=ad,dc=sostup,dc=id")
	cli.Flag(&flags.dc, "dc", "", "Identify domain controller")
	cli.Flag(&flags.insecure, "insecure", false, "Use ldap:// instead of ldaps://")
	cli.Flag(&flags.password, "p", false, "Password to bind with, will prompt")
	cli.Flag(&flags.passwordcli, "password", "", "Password to bind with, provided on command line")
	cli.Flag(&flags.username, "u", "user", "", "Username to bind with")
	cli.Flag(&flags.skipVerify, "s", "skip", false, "Skip SSL verification")
	cli.Flag(&flags.searchscope, "scope", 2, "Define scope of search, 0=Base, 1=Single Level, 2=Whole Sub Tree, 3=Children, only used by filter and objectquery")
	cli.Flag(&flags.pth, "pth", "", "Bind with password hash, WHY IS THIS SUPPORTED OTB?!")
	cli.Flag(&flags.verbose, "v", "verbose", false, "Enable verbose output")

	cli.Parse()

	// Check for dc, because wtf are we going to connect to without it
	if flags.dc == "" {
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
			log.Fatalf("Usage: ldaptickler %s %s", cli.Arg(0), act.usage)
		}
	}

	/* Various checks for flag combinations that don't make sense.
	Allowing a username for anonymous binds since the spec for LDAP allows it for tracking purposes.
	Reading password using term.ReadPassword to prevent echoing of the credential or needing it in plain text.
	*/

	if flags.password && flags.pth != "" {
		log.Fatal("[-] Silly Goose detected, you can't PTH and provide a password")
	}

	if flags.passwordcli != "" && flags.pth != "" {
		log.Fatal("[-] Silly Goose detected, you can't PTH and provide a password")
	}

	if flags.password || flags.gssapi {
		state.mode = ldaptickler.MethodBindPassword
		if flags.gssapi {
			state.mode = ldaptickler.MethodBindGSSAPI
		}
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

	if flags.passwordcli != "" {
		state.password = flags.passwordcli
		if !flags.gssapi {
			state.mode = ldaptickler.MethodBindPassword
		}
		if flags.gssapi {
			state.mode = ldaptickler.MethodBindGSSAPI
		}
		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
		state.password = flags.passwordcli
	}

	if flags.domain != "" {
		if !flags.gssapi {
			state.mode = ldaptickler.MethodBindDomain
		}
		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
	}

	if flags.pth != "" || flags.gssapi {
		if !flags.gssapi {
			state.mode = ldaptickler.MethodBindDomainPTH
		}
		if flags.domain == "" {
			log.Fatal("[-] Domain is empty, unable to continue\n")
		}

		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
	}

	if flags.basedn == "" {
		log.Fatal("[-] A basedn will be required for any action")
	}
	if flags.verbose {
		ldaptickler.LDAPDebug = true
	} else {
		ldaptickler.LDAPDebug = false
	}

}

func main() {
	var proto string = "ldaps://"
	if flags.insecure {
		proto = "ldap://"
	}
	// add flag dbag
	//ldaptickler.LDAPDebug = false
	var c *ldaptickler.Conn = ldaptickler.New(proto+flags.dc, flags.basedn, flags.skipVerify)
	var err error
	// Attempt anonymous bind, check for flag
	switch state.mode {
	case ldaptickler.MethodBindAnonymous:
		fmt.Printf("[+] Attempting anonymous bind to %s\n", flags.dc)
		err = c.BindAnonymous(flags.username)

	case ldaptickler.MethodBindDomain:
		fmt.Printf("[+] Attempting NTLM bind to %s\n", flags.dc)
		err = c.BindDomain(flags.domain, flags.username, state.password)

	case ldaptickler.MethodBindDomainPTH:
		fmt.Printf("[+] Attempting NTLM Pass The Hash bind to %s\n", flags.dc)
		err = c.BindDomainPTH(flags.domain, flags.username, flags.pth)

	case ldaptickler.MethodBindPassword:
		fmt.Printf("[+] Attempting bind with credentials to %s\n", flags.dc)
		err = c.BindPassword(flags.username, state.password)

	case ldaptickler.MethodBindGSSAPI:
		fmt.Printf("[+] Attempting GSSAPI bind to %s\n", flags.dc)
		err = c.BindGSSAPI(flags.domain, flags.username, state.password, "ldap/"+flags.dc)
	}
	check(err)
	defer c.Close()
	fmt.Printf("[+] Successfully connected to %s\n", flags.dc)
	err = lookupTable[strings.ToLower(cli.Arg(0))].call(c, cli.Args()[1:]...)
	check(err)
	if err == nil {
		os.Exit(0)
	}
}

func addmachine(c *ldaptickler.Conn, args ...string) error {
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

func addmachinelp(c *ldaptickler.Conn, args ...string) error {
	machinename := args[0]
	machinepass := args[1]
	domain := args[2]

	err := c.AddMachineAccountLowPriv(machinename, machinepass, domain)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Added machine account %s successfully with password %s\n", machinename, machinepass)
	return nil
}

func addspn(c *ldaptickler.Conn, args ...string) error {
	machinename := args[0]
	spn := args[1]
	fmt.Printf("[+] Adding spn %s to machine account %s\n", spn, machinename)
	err := c.AddServicePrincipalName(machinename, spn)
	check(err)
	fmt.Printf("[+] Successfully added spn %s to machine account %s\n", spn, machinename)
	return nil
}

func adduser(c *ldaptickler.Conn, args ...string) error {
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

func certpublishers(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Certificate Publishers in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListCAs()
	check(err)
	return nil
}

func changepassword(c *ldaptickler.Conn, args ...string) error {
	username := args[0]
	userpasswd := args[1]

	fmt.Printf("[+] Changing password for user %s with password supplied in LDAP with baseDN %s\n", username, flags.basedn)
	err := c.SetUserPassword(username, userpasswd)
	check(err)
	fmt.Printf("[+] Password change successful for user %s\n", username)
	return nil
}

func computers(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all computers in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListComputers()
	check(err)
	return nil
}

func constraineddelegation(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Constrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListConstrainedDelegation()
	check(err)
	return nil
}

func deleteobject(c *ldaptickler.Conn, args ...string) error {
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

func disablemachine(c *ldaptickler.Conn, args ...string) error {
	objectname := cli.Arg(1)
	err := c.SetDisableMachineAccount(objectname)
	check(err)
	fmt.Printf("[+] Machine account %s disabled\n", objectname)
	return nil
}

func disablecd(c *ldaptickler.Conn, args ...string) error {
	samaccountname := args[0]
	spn := args[1]
	fmt.Printf("[+] Removing constrained delegation spn %s from %s \n", spn, samaccountname)
	err := c.RemoveConstrainedDelegation(samaccountname, spn)
	check(err)
	return nil
}

func disablerbcd(c *ldaptickler.Conn, args ...string) error {
	samaccountname := args[0]
	fmt.Printf("[+] Removing RBCD from %s\n", samaccountname)
	err := c.RemoveResourceBasedConstrainedDelegation(samaccountname)
	check(err)
	return nil
}

func disableud(c *ldaptickler.Conn, args ...string) error {
	samaccountname := args[0]
	fmt.Printf("[+] Removing unconstrained delegation from %s\n", samaccountname)
	err := c.RemoveUnconstrainedDelegation(samaccountname)
	check(err)
	return nil
}

func disablespn(c *ldaptickler.Conn, args ...string) error {
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

func disableuser(c *ldaptickler.Conn, args ...string) error {
	objectname := cli.Arg(1)
	err := c.SetDisableUserAccount(objectname)
	check(err)
	fmt.Printf("[+] User account %s disabled\n", objectname)
	return nil
}

func dnsrecords(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all DNS records in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListDNS()
	check(err)
	return nil
}

func domaincontrollers(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Domain Controllers in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListDCs()
	check(err)
	return nil
}

func enablemachine(c *ldaptickler.Conn, args ...string) error {
	objectname := cli.Arg(1)
	err := c.SetEnableMachineAccount(objectname)
	check(err)
	fmt.Printf("[+] Machine account %s enabled\n", objectname)
	return nil
}

func enablecd(c *ldaptickler.Conn, args ...string) error {
	samaccountname := args[0]
	spn := args[1]
	fmt.Printf("[+] Adding constrained delegation spn %s to %s\n", spn, samaccountname)
	err := c.AddConstrainedDelegation(samaccountname, spn)
	check(err)
	return nil
}

func enableud(c *ldaptickler.Conn, args ...string) error {
	samaccountname := args[0]
	fmt.Printf("[+] Adding unconstrained delegation to %s\n", samaccountname)
	err := c.AddUnconstrainedDelegation(samaccountname)
	check(err)
	return nil
}

func enablerbcd(c *ldaptickler.Conn, args ...string) error {
	samaccountname := args[0]
	delegatingcomputer := args[1]
	fmt.Printf("[+] Adding RBCD to %s setting delegation for %s\n", samaccountname, delegatingcomputer)
	err := c.AddResourceBasedConstrainedDelegation(samaccountname, delegatingcomputer)
	check(err)
	return nil
}

func enableuser(c *ldaptickler.Conn, args ...string) error {
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

func filter(c *ldaptickler.Conn, args ...string) error {
	filter := cli.Arg(1)
	fmt.Printf("[+] Searching with specified filter: %s in LDAP with baseDN %s\n", filter, flags.basedn)
	err := c.LDAPSearch(flags.searchscope, filter, expandlist(flags.attributes))
	check(err)
	return nil
}

func groups(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all groups in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListGroups()
	check(err)
	return nil
}

func groupswithmembers(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all groups and their members in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListGroupswithMembers()
	check(err)
	return nil
}

func kerberoastable(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Kerberoastable users in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListKerberoastable()
	check(err)
	return nil
}

func machineaccountquota(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for ms-DS-MachineAccountQuota in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListMachineAccountQuota()
	check(err)
	return nil
}

func machinecreationdacl(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for ms-DS-MachineCreationRestrictedToDACL in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListMachineCreationDACL()
	check(err)
	return nil
}

func nopassword(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users not required to have a password in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListNoPassword()
	check(err)
	return nil
}

func objectquery(c *ldaptickler.Conn, args ...string) error {
	objectname := cli.Arg(1)
	fmt.Printf("[+] Searching for attributes of object %s in LDAP with baseDN %s\n", objectname, flags.basedn)
	err := c.FindUserByName(objectname, flags.searchscope)
	check(err)
	return nil
}

func passworddontexpire(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users all objects where the password doesn't expire in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListPasswordDontExpire()
	check(err)
	return nil
}

func passwordchangenextlogin(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users all objects where the password is set to change at next login in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListPasswordChangeNextLogin()
	check(err)
	return nil
}

func protectedusers(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users in Protected Users group in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListProtectedUsers()
	check(err)
	return nil
}

func preauthdisabled(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Kerberos Pre-auth Disabled users in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListPreAuthDisabled()
	check(err)
	return nil
}

func querydescription(c *ldaptickler.Conn, args ...string) error {
	querydescription := cli.Arg(1)
	fmt.Printf("[+] Searching all objects for a description of %s in LDAP with baseDN %s\n", querydescription, flags.basedn)
	err := c.FindUserByDescription(querydescription)
	check(err)
	return nil
}

func rbcd(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Resource Based Constrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListRBCD()
	check(err)
	return nil
}

func schema(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Listing schema for LDAP database with baseDN %s\n", flags.basedn)
	err := c.ListSchema()
	check(err)
	return nil
}

func shadowcredentials(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Shadow Credentials in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListShadowCredentials()
	check(err)
	return nil
}

func unconstraineddelegation(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all Unconstrained Delegation objects in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListUnconstrainedDelegation()
	check(err)
	return nil
}

func users(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Searching for all users in LDAP with baseDN %s\n", flags.basedn)
	err := c.ListUsers(expandlist(flags.attributes)...)
	check(err)
	return nil
}

func whoami(c *ldaptickler.Conn, args ...string) error {
	fmt.Printf("[+] Querying the LDAP server for WhoAmI with baseDN %s\n", flags.basedn)
	result, err := c.GetWhoAmI()
	check(err)
	fmt.Printf("[+] You are currently authenticated as %+v\n", *result)
	return nil
}
