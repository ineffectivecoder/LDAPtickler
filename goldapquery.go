package goldapquery

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// BindMethod TODO
type BindMethod int

// Conn TODO
type Conn struct {
	lconn *ldap.Conn
}

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
	SkipVerify bool
	BaseDN     string
)

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

// Bind will TODO
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

func (c *Conn) Close() error {
	return c.lconn.Close()
}

func (c *Conn) ldapSearch(searchscope int, filter string, attributes []string) (*ldap.SearchResult, error) {
	var err error
	var result *ldap.SearchResult
	searchReq := ldap.NewSearchRequest(BaseDN, searchscope, 0, 0, 0, false, filter, attributes, []ldap.Control{})
	result, err = c.lconn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	return result, err
}

func (c *Conn) LDAPSearch(searchscope int, filter string, attributes []string) error {
	var err error
	var result *ldap.SearchResult
	result, err = c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListCAs() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(samaccountname=Cert Publishers)(member=*) "
	attributes := []string{"member"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListConstrainedDelegation() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectClass=User)(msDS-AllowedToDelegateTo=*))"
	attributes := []string{"samaccountname", "msDS-AllowedToDelegateTo"}
	searchscope := 2
	// ldapSearch(l, flags.basedn, searchscope, filter, attributes)
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListDCs() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListComputers() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(objectClass=computer)"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListGroups() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(objectCategory=group)"
	attributes := []string{"sAMAccountName"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListGroupswithMembers() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectCategory=group)(samaccountname=*)(member=*))"
	attributes := []string{"member"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListKerberoastable() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectClass=User)(serviceprincipalname=*)(samaccountname=*))"
	attributes := []string{"samaccountname", "serviceprincipalname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListMachineAccountQuota() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(objectClass=*)"
	attributes := []string{"ms-DS-MachineAccountQuota"}
	searchscope := 0
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListNoPassword() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListPasswordDontExpire() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListPasswordChangeNextLogin() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListProtectedUsers() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(samaccountname=Protected Users)(member=*))"
	attributes := []string{"member"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListPreAuthDisabled() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListRBCD() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	attributes := []string{"samaccountname", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListShadowCredentials() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(msDS-KeyCredentialLink=*)"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListUnconstrainedDelegation() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}

func (c *Conn) ListUsers() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectCategory=person)(objectClass=user))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.ldapSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}
