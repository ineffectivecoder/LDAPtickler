package goldapquery

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
)

// BindMethod TODO
type BindMethod int

// These enums are bind methods for the bind function
const (
	MethodBindAnonymous = iota
	MethodBindPassword
	MethodBindDomain
	MethodBindDomainPTH
	MethodBindSASL
	MethodBindGSSAPI
)

// Enums for modification of useraccountcontrol field
const (
	UACScript                       = 0x1
	UACAccountDisable               = 0x2
	UACHomeDirRequired              = 0x8
	UACLockout                      = 0x10
	UACPasswdNotRequired            = 0x20
	UACPasswordCantChange           = 0x40
	UACEncryptedTextPasswordAllowed = 0x80
	UACTempDuplicateAccount         = 0x100
	UACNormalAccount                = 0x200
	UACInterdomainTrustAccount      = 0x800
	UACWorkstationTrustAccount      = 0x1000
	UACServerTrustAccount           = 0x2000
	UACDontExpirePassword           = 0x10000
	UACMNSLogonAccount              = 0x20000
	UACSmartCardRequired            = 0x40000
	UACTrustedForDelegation         = 0x80000
	UACNotDelegated                 = 0x100000
	UACDesKeyOnly                   = 0x200000
	UACDontReqPreAuth               = 0x400000
	UACPasswordRequired             = 0x800000
	UACTrustedToAuthForDelegation   = 0x1000000
	UACPartialSecretsAccount        = 0x4000000
)

// Conn gives us a structure named lconn linked to *ldap.Conn
type Conn struct {
	lconn      *ldap.Conn
	baseDN     string
	skipVerify bool
	url        string
}

// New TODO
func New(url string, basedn string, skipVerify ...bool) *Conn {
	var connection *Conn = &Conn{url: url, baseDN: basedn}
	if len(skipVerify) > 0 {
		connection.skipVerify = skipVerify[0]
	}
	return connection
}

func (c *Conn) bindSetup() error {
	var err error
	// fmt.Printf("[+] skipVerify currently set to %t\n", skipVerify)
	if strings.HasPrefix(c.url, "ldaps:") {
		// ServerName: "0.0.0.0", MaxVersion: tls.VersionTLS12
		c.lconn, err = ldap.DialURL(c.url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: c.skipVerify}))
	} else {
		if !strings.HasPrefix(c.url, "ldap:") {
			c.url = "ldap://" + c.url
		}
		c.lconn, err = ldap.DialURL(c.url)
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) createUnicodePasswordRequest(username string, password string) (*ldap.ModifyRequest, error) {
	passwordSet := ldap.NewModifyRequest("CN="+username+",CN=Users,"+c.baseDN, nil)
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	newunicodeEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("%q", password))
	if err != nil {
		return nil, err
	}
	passwordSet.Replace("unicodePwd", []string{newunicodeEncoded})
	return passwordSet, nil
}

func encodePassword(password string) string {
	quoted := fmt.Sprintf("\"%s\"", password)
	encoded := ""
	for _, r := range quoted {
		encoded += fmt.Sprintf("%c%c", byte(r), 0)
	}
	return encoded
}

// BindAnonymous will attempt to bind to the specified URL with an optional username.
func (c *Conn) BindAnonymous(username string) error {
	var err error
	err = c.bindSetup()
	if err != nil {
		return err
	}
	err = c.lconn.UnauthenticatedBind(username)
	if err != nil {
		return err
	}
	return nil
}

// BindDomain will attempt to bind to the specified URL with a username, password and domain.
func (c *Conn) BindDomain(domain string, username string, password string) error {
	var err error
	err = c.bindSetup()
	if err != nil {
		return err
	}
	err = c.lconn.NTLMBind(domain, username, password)
	if err != nil {
		return err
	}
	return nil
}

// BindDomainPTH will attempt to bind to the specified URL with a username, password hash and domain.
func (c *Conn) BindDomainPTH(domain string, username string, hash string) error {
	var err error
	err = c.bindSetup()
	if err != nil {
		return err
	}
	err = c.lconn.NTLMBindWithHash(domain, username, hash)
	if err != nil {
		return err
	}
	return nil
}

// BindPassword will attempt a simple bind to the specified  URL with supplied username and password
func (c *Conn) BindPassword(username string, password string) error {
	var err error
	err = c.bindSetup()
	if err != nil {
		return err
	}
	err = c.lconn.Bind(username, password)
	if err != nil {
		return err
	}
	return nil
}

// AddUnconstrainedDelegation will modify the useraccountcontrol field to enable unconstrained delegation
func (c *Conn) AddUnconstrainedDelegation(username string) error {
	filter := "(samaccountname=" + username + ")"
	attributes := []string{"distinguishedName"}
	searchscope := 2
	dn, err := c.getFirstResult(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	attributes = []string{"useraccountcontrol"}
	uacstr, err := c.getFirstResult(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	uac, err := flagset(uacstr, UACTrustedForDelegation)
	if err != nil {
		return err
	}
	// fmt.Printf("cn=%08x\n", uac)
	// Get value for UAC, and then apply value to bitmask
	enableReq := ldap.NewModifyRequest(dn, []ldap.Control{})
	enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(enableReq)
}

// RemoveUnconstrainedDelegation will modify the useraccountcontrol field to disable unconstrained delegation
func (c *Conn) RemoveUnconstrainedDelegation(username string) error {
	filter := "(samaccountname=" + username + ")"
	attributes := []string{"distinguishedName"}
	searchscope := 2
	dn, err := c.getFirstResult(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	attributes = []string{"useraccountcontrol"}
	uacstr, err := c.getFirstResult(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	uac, err := flagunset(uacstr, UACTrustedForDelegation)
	if err != nil {
		return err
	}
	// Get value for UAC, and then apply value to bitmask
	enableReq := ldap.NewModifyRequest(dn, []ldap.Control{})
	enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(enableReq)
}

// AddMachineAccount will attempt to add a machine account for the supplied machinename and machinepass
func (c *Conn) AddMachineAccount(machinename string, machinepass string) error {
	addReq := ldap.NewAddRequest("CN="+machinename+",CN=Computers,"+c.baseDN, []ldap.Control{})
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("cn", []string{machinename})
	addReq.Attribute("sAMAccountName", []string{machinename + "$"})
	addReq.Attribute("userAccountControl", []string{"4096"}) // WORKSTATION_TRUST_ACCOUNT
	encodedPassword := encodePassword(machinepass)
	addReq.Attribute("unicodePWD", []string{encodedPassword})
	return c.lconn.Add(addReq)
}

// AddUserAccount will attempt to add a user account for the supplied username, note this requires SetUserPassword and
// SetEnableAccount to function
func (c *Conn) AddUserAccount(username string, principalname string) error {
	addReq := ldap.NewAddRequest("CN="+username+",CN=Users,"+c.baseDN, []ldap.Control{})
	addReq.Attribute("accountExpires", []string{fmt.Sprintf("%d", 0x00000000)})
	addReq.Attribute("cn", []string{username})
	addReq.Attribute("displayName", []string{username})
	addReq.Attribute("givenName", []string{username})
	addReq.Attribute("instanceType", []string{fmt.Sprintf("%d", 0x00000004)})
	addReq.Attribute("name", []string{username})
	addReq.Attribute("objectClass", []string{"top", "organizationalPerson", "user", "person"})
	addReq.Attribute("sAMAccountName", []string{username})
	addReq.Attribute("sn", []string{username})
	// Create the account disabled....
	addReq.Attribute("userAccountControl", []string{"514"})
	addReq.Attribute("userPrincipalName", []string{principalname})
	// addReq.Attributes = attrs
	return c.lconn.Add(addReq)
}

// Close closes the LDAP connection
func (c *Conn) Close() error {
	if c.lconn == nil {
		return nil
	}
	return c.lconn.Close()
}

// DeleteObject will attempt to delete the object specified, currently supports users and computers
// REDO THIS, change to deletemachine and deleteuser, deletegpo?
func (c *Conn) DeleteObject(objectname string, objecttype string) error {
	var cn string = "Users"
	if objecttype == "m" {
		// May need to rethink this, some objects actually have the $ in the CN name
		cn = "Computers"
	}
	delReq := ldap.NewDelRequest("CN="+objectname+",CN="+cn+","+c.baseDN, []ldap.Control{})
	return c.lconn.Del(delReq)
}

// FindUserByDescription will search the directory for a specified query description
func (c *Conn) FindUserByDescription(querydescription string) error {
	filter := "(&(objectCategory=*)(description=" + querydescription + "))"
	attributes := []string{"samaccountname", "description"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// FindUserByName will search the directory for a specified username
func (c *Conn) FindUserByName(objectquery string, searchscope int) error {
	filter := "(&(objectClass=user)(samaccountname=" + objectquery + "))"
	attributes := []string{"*"}
	return c.LDAPSearch(searchscope, filter, attributes)
}

func flagset(data string, flag int) (int, error) {
	i, err := strconv.Atoi(data)
	if err != nil {
		return 0, err
	}
	// Apply bitmask to disable
	i = i | flag // 0x2
	return i, nil
}

func flagunset(data string, flag int) (int, error) {
	i, err := strconv.Atoi(data)
	if err != nil {
		return 0, err
	}
	// Apply bitmask to enable
	i = i & ^flag // 0x2
	return i, nil
}

func (c *Conn) getFirstResult(searchscope int, filter string, attributes []string) (string, error) {
	result, err := c.ldapSearch(c.baseDN, searchscope, filter, attributes)
	if err != nil {
		return "", err
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no entries found") // custom error result not found
	}
	if len(result.Entries[0].Attributes) == 0 {
		return "", fmt.Errorf("entry has no attributes") // custom error attribute missing
	}
	if len(result.Entries[0].Attributes[0].Values) == 0 {
		return "", fmt.Errorf("entry has no values")
	}
	return result.Entries[0].Attributes[0].Values[0], nil
}

// GetWhoAmI will query the LDAP server for who we currently are authenticated as
func (c *Conn) GetWhoAmI() (*ldap.WhoAmIResult, error) {
	result, err := c.lconn.WhoAmI(nil)
	if err != nil {
		return nil, err
	}
	return result, err
}

func (c *Conn) ldapSearch(basedn string, searchscope int, filter string, attributes []string) (*ldap.SearchResult, error) {
	if c.lconn == nil {
		return nil, fmt.Errorf("you must bind before searching")
	}
	var err error
	var result *ldap.SearchResult
	searchReq := ldap.NewSearchRequest(basedn, searchscope, 0, 0, 0, false, filter, attributes, []ldap.Control{})
	result, err = c.lconn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	return result, err
}

// LDAPSearch will search the directory by a supplied searchscope, filter and attributes
func (c *Conn) LDAPSearch(searchscope int, filter string, attributes []string) error {
	var err error
	var result *ldap.SearchResult
	result, err = c.ldapSearch(c.baseDN, searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

// ListCAs will search the directory for all Cert Publishers or CAs in the domain
func (c *Conn) ListCAs() error {
	filter := "(&(samaccountname=Cert Publishers)(member=*) "
	attributes := []string{"member"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListConstrainedDelegation will search the directory for objects configured for Unconstrained Delegation
func (c *Conn) ListConstrainedDelegation() error {
	filter := "(&(objectClass=User)(msDS-AllowedToDelegateTo=*))"
	attributes := []string{"samaccountname", "msDS-AllowedToDelegateTo"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListComputers will search the directory for all computer/machine account objects
func (c *Conn) ListComputers() error {
	filter := "(objectClass=computer)"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListDCs will search the directory for all Domain Controllers
func (c *Conn) ListDCs() error {
	filter := "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListGroups will search the directory for all Groups
func (c *Conn) ListGroups() error {
	filter := "(objectCategory=group)"
	attributes := []string{"sAMAccountName"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListGroupswithMembers will search the directory for all Groups and their members
func (c *Conn) ListGroupswithMembers() error {
	filter := "(&(objectCategory=group)(samaccountname=*)(member=*))"
	attributes := []string{"member"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListKerberoastable will search the directory for all Kerberoastable users
func (c *Conn) ListKerberoastable() error {
	filter := "(&(objectClass=User)(serviceprincipalname=*)(samaccountname=*))"
	attributes := []string{"samaccountname", "serviceprincipalname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListMachineAccountQuota will identify the number of machine accounts users are allowed to add to the domain
func (c *Conn) ListMachineAccountQuota() error {
	filter := "(objectClass=*)"
	attributes := []string{"ms-DS-MachineAccountQuota"}
	searchscope := 0
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListNoPassword will identify any users who aren't required to have a password
func (c *Conn) ListNoPassword() error {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListPasswordChangeNextLogin will identify any users who are required to change their password at next login
func (c *Conn) ListPasswordChangeNextLogin() error {
	filter := "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListPasswordDontExpire will identify any users who have a password that is not required to be changed after a specific amount of time
func (c *Conn) ListPasswordDontExpire() error {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListPreAuthDisabled will identify any accounts where preauthentication is disabled
func (c *Conn) ListPreAuthDisabled() error {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListProtectedUsers will identify any accounts in the Protected Users group
func (c *Conn) ListProtectedUsers() error {
	filter := "(&(samaccountname=Protected Users)(member=*))"
	attributes := []string{"member"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListRBCD will identify all objects configured for RBCD
func (c *Conn) ListRBCD() error {
	filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	attributes := []string{"samaccountname", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListSchema will list the schema of the directory
func (c *Conn) ListSchema() error {
	filter := "(objectClass=*)"
	attributes := []string{}
	searchscope := 0
	var err error
	var result *ldap.SearchResult
	result, err = c.ldapSearch("cn=Schema,cn=Configuration,"+c.baseDN, searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

// ListShadowCredentials will identify any accounts configured with Shadow Credentials
func (c *Conn) ListShadowCredentials() error {
	filter := "(msDS-KeyCredentialLink=*)"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListUnconstrainedDelegation will identify any accounts configured for Unconstrained Delegation
func (c *Conn) ListUnconstrainedDelegation() error {
	// It is doing the bitmasking for us, must use decimal value. Bitmask is 80000
	filter := "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
	attributes := []string{"samaccountname", "useraccountcontrol"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// ListUsers will identify all user objects. This may be overridden with multiple attributes changing the functionality.
func (c *Conn) ListUsers(attributes ...string) error {
	filter := "(&(objectCategory=person)(objectClass=user))"
	if len(attributes) == 0 {
		attributes = []string{"samaccountname"}
	}

	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// SetDisableMachineAccount will modify the userAccountControl attribute to disable a machine account
func (c *Conn) SetDisableMachineAccount(username string) error {
	filter := "(&(objectClass=computer)(samaccountname=" + username + "))"
	attributes := []string{"useraccountcontrol"}
	searchscope := 2

	uacstr, err := c.getFirstResult(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	uac, err := flagset(uacstr, UACAccountDisable)
	if err != nil {
		return err
	}
	// Get value for UAC, and then apply value to bitmask
	disableReq := ldap.NewModifyRequest("CN="+strings.TrimSuffix(username, "$")+",CN=Computers,"+c.baseDN, []ldap.Control{})
	disableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(disableReq)
}

// SetEnableMachineAccount will modify the userAccountControl attribute to enable a machine account
func (c *Conn) SetEnableMachineAccount(username string) error {
	filter := "(&(objectClass=computer)(samaccountname=" + username + "))"
	attributes := []string{"useraccountcontrol"}
	searchscope := 2
	uacstr, err := c.getFirstResult(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	uac, err := flagunset(uacstr, UACAccountDisable)
	if err != nil {
		return err
	}
	// Get value for UAC, and then apply value to bitmask
	enableReq := ldap.NewModifyRequest("CN="+strings.TrimSuffix(username, "$")+",CN=Computers,"+c.baseDN, []ldap.Control{})
	enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(enableReq)
}

// SetDisableUserAccount will modify the userAccountControl attribute to disable a user account
func (c *Conn) SetDisableUserAccount(username string) error {
	filter := "(&(objectClass=person)(samaccountname=" + username + "))"
	attributes := []string{"useraccountcontrol"}
	searchscope := 2

	uacstr, err := c.getFirstResult(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	uac, err := flagset(uacstr, UACAccountDisable)
	if err != nil {
		return err
	}
	disableReq := ldap.NewModifyRequest("CN="+username+",CN=Users,"+c.baseDN, []ldap.Control{})
	disableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(disableReq)
}

// SetEnableUserAccount will modify the userAccountControl attribute to enable a user account
func (c *Conn) SetEnableUserAccount(username string) error {
	filter := "(&(objectClass=person)(samaccountname=" + username + "))"
	attributes := []string{"useraccountcontrol"}
	searchscope := 2

	uacstr, err := c.getFirstResult(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	uac, err := flagunset(uacstr, UACAccountDisable)
	if err != nil {
		return err
	}
	enableReq := ldap.NewModifyRequest("CN="+username+",CN=Users,"+c.baseDN, []ldap.Control{})
	enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(enableReq)
}

// SetUserPassword will set a user account's password
func (c *Conn) SetUserPassword(username string, userpass string) error {
	passwordReq, err := c.createUnicodePasswordRequest(username, userpass)
	if err != nil {
		return err
	}
	return c.lconn.Modify(passwordReq)
}
