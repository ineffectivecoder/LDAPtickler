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

func (c *Conn) LDAPSearch(searchscope int, filter string, attributes []string) (*ldap.SearchResult, error) {
	var err error
	var result *ldap.SearchResult
	searchReq := ldap.NewSearchRequest(BaseDN, searchscope, 0, 0, 0, false, filter, attributes, []ldap.Control{})
	result, err = c.lconn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	return result, err
}

func (c *Conn) ListDCs() error {
	if c.lconn == nil {
		return fmt.Errorf("you must bind before searching")
	}
	filter := "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
	attributes := []string{"samaccountname"}
	searchscope := 2
	result, err := c.LDAPSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	result.PrettyPrint(2)
	return nil
}
