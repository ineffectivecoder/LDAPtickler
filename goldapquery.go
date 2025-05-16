package goldapquery

import (
	"crypto/tls"
	"fmt"
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

var (
	// SkipVerify will TODO
	SkipVerify bool
	// BaseDN will TODO
	BaseDN string
)

// Conn TODO
type Conn struct {
	lconn *ldap.Conn
}

func bindSetup(
	url string,
) (*ldap.Conn, error) {
	var l *ldap.Conn
	var err error
	// fmt.Printf("[+] skipVerify currently set to %t\n", skipVerify)
	if strings.HasPrefix(url, "ldaps:") {
		// ServerName: "0.0.0.0", MaxVersion: tls.VersionTLS12
		l, err = ldap.DialURL(url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: SkipVerify}))
	} else {
		if !strings.HasPrefix(url, "ldap:") {
			url = "ldap://" + url
		}
		l, err = ldap.DialURL(url)
	}
	if err != nil {
		return nil, err
	}
	return l, nil
}

func createUnicodePasswordRequest(username string, password string) (*ldap.ModifyRequest, error) {
	passwordSet := ldap.NewModifyRequest("CN="+username+",CN=Users,"+BaseDN, nil)
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

// BindAnonymous will TODO
func BindAnonymous(url string, username string) (*Conn, error) {
	var l *ldap.Conn
	var err error
	l, err = bindSetup(url)
	if err != nil {
		return nil, err
	}
	err = l.UnauthenticatedBind(username)
	if err != nil {
		return nil, err
	}
	return &Conn{lconn: l}, nil
}

// BindDomain will TODO
func BindDomain(url string, domain string, username string, password string) (*Conn, error) {
	var l *ldap.Conn
	var err error
	l, err = bindSetup(url)
	if err != nil {
		return nil, err
	}
	err = l.NTLMBind(domain, username, password)
	if err != nil {
		return nil, err
	}
	return &Conn{lconn: l}, nil
}

// BindDomainPTH will TODO
func BindDomainPTH(url string, domain string, username string, hash string) (*Conn, error) {
	var l *ldap.Conn
	var err error
	l, err = bindSetup(url)
	if err != nil {
		return nil, err
	}
	err = l.NTLMBindWithHash(domain, username, hash)
	if err != nil {
		return nil, err
	}
	return &Conn{lconn: l}, nil
}

// BindPassword will TODO
func BindPassword(url string, username string, password string) (*Conn, error) {
	var l *ldap.Conn
	var err error
	l, err = bindSetup(url)
	if err != nil {
		return nil, err
	}
	err = l.Bind(username, password)
	if err != nil {
		return nil, err
	}
	return &Conn{lconn: l}, nil
}

func (c *Conn) AddMachineAccount(machinename string, machinepass string) error {
	addReq := ldap.NewAddRequest("CN="+machinename+",CN=Computers,"+BaseDN, []ldap.Control{})
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("cn", []string{machinename})
	addReq.Attribute("sAMAccountName", []string{machinename + "$"})
	addReq.Attribute("userAccountControl", []string{"4096"}) // WORKSTATION_TRUST_ACCOUNT
	encodedPassword := encodePassword(machinepass)
	addReq.Attribute("unicodePWD", []string{encodedPassword})
	return c.lconn.Add(addReq)
}

func (c *Conn) AddUserAccount(username string, principalname string) error {
	addReq := ldap.NewAddRequest("CN="+username+",CN=Users,"+BaseDN, []ldap.Control{})
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

func (c *Conn) Close() error {
	if c.lconn == nil {
		return nil
	}
	return c.lconn.Close()
}

func (c *Conn) DeleteObject(objectname string) error {
	var cn string = "Users"
	if strings.HasSuffix(objectname, "$") {
		objectname = strings.TrimSuffix(objectname, "$")
		cn = "Computers"
	}
	delReq := ldap.NewDelRequest("CN="+objectname+",CN="+cn+","+BaseDN, []ldap.Control{})
	return c.lconn.Del(delReq)
}

func (c *Conn) FindUserByDescription(querydescription string) error {
	filter := "(&(objectCategory=*)(description=" + querydescription + "))"
	attributes := []string{"samaccountname", "description"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) FindUserByName(objectquery string, searchscope int) error {
	filter := "(&(objectClass=user)(samaccountname=" + objectquery + "))"
	attributes := []string{"*"}
	return c.LDAPSearch(searchscope, filter, attributes)
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

func (c *Conn) LDAPSearch(searchscope int, filter string, attributes []string) error {
	var err error
	var result *ldap.SearchResult
	result, err = c.ldapSearch(BaseDN, searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListCAs() error {
	filter := "(&(samaccountname=Cert Publishers)(member=*) "
	attributes := []string{"member"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListConstrainedDelegation() error {
	filter := "(&(objectClass=User)(msDS-AllowedToDelegateTo=*))"
	attributes := []string{"samaccountname", "msDS-AllowedToDelegateTo"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListComputers() error {
	filter := "(objectClass=computer)"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListDCs() error {
	filter := "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListGroups() error {
	filter := "(objectCategory=group)"
	attributes := []string{"sAMAccountName"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListGroupswithMembers() error {
	filter := "(&(objectCategory=group)(samaccountname=*)(member=*))"
	attributes := []string{"member"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListKerberoastable() error {
	filter := "(&(objectClass=User)(serviceprincipalname=*)(samaccountname=*))"
	attributes := []string{"samaccountname", "serviceprincipalname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListMachineAccountQuota() error {
	filter := "(objectClass=*)"
	attributes := []string{"ms-DS-MachineAccountQuota"}
	searchscope := 0
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListNoPassword() error {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListPasswordChangeNextLogin() error {
	filter := "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListPasswordDontExpire() error {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListPreAuthDisabled() error {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListProtectedUsers() error {
	filter := "(&(samaccountname=Protected Users)(member=*))"
	attributes := []string{"member"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListRBCD() error {
	filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	attributes := []string{"samaccountname", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListSchema() error {
	filter := "(objectClass=*)"
	attributes := []string{}
	searchscope := 0
	var err error
	var result *ldap.SearchResult
	result, err = c.ldapSearch("cn=Schema,cn=Configuration,"+BaseDN, searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListShadowCredentials() error {
	filter := "(msDS-KeyCredentialLink=*)"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListUnconstrainedDelegation() error {
	filter := "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) ListUsers() error {
	filter := "(&(objectCategory=person)(objectClass=user))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

func (c *Conn) SetEnableAccount(username string) error {
	enableReq := ldap.NewModifyRequest("CN="+username+",CN=Users,"+BaseDN, []ldap.Control{})
	enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", 0x0200)})
	return c.lconn.Modify(enableReq)
}

func (c *Conn) SetUserPassword(username string, userpass string) error {
	passwordReq, err := createUnicodePasswordRequest(username, userpass)
	if err != nil {
		return err
	}
	return c.lconn.Modify(passwordReq)
}
