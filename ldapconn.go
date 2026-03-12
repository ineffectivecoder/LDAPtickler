package ldaptickler

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/iana/flags"
	"github.com/jcmturner/gokrb5/v8/client"
	"golang.org/x/net/proxy"
)

type LDAPConn struct {
	gssClient  *gssapi.Client
	lconn      *ldap.Conn
	proxyURL   string
	skipVerify bool
	url        string
	username   string
}

func (c *LDAPConn) Add(dn string, attrs map[string][]string) error {
	request := ldap.NewAddRequest(dn, nil)
	for attr, attrvals := range attrs {
		request.Attribute(attr, attrvals)
	}
	return c.lconn.Add(request)
}

func (c *LDAPConn) ModifyAdd(dn string, attr string, attrvals []string) error {
	request := ldap.NewModifyRequest(dn, nil)
	request.Add(attr, attrvals)
	return c.lconn.Modify(request)
}

func (c *LDAPConn) ModifyDelete(dn string, attr string) error {
	request := ldap.NewModifyRequest(dn, nil)
	request.Delete(attr, nil)
	return c.lconn.Modify(request)
}

func (c *LDAPConn) ModifyReplace(dn string, attr string, attrvals []string) error {
	request := ldap.NewModifyRequest(dn, nil)
	request.Replace(attr, attrvals)
	return c.lconn.Modify(request)
}

func (c *LDAPConn) Bind(url string, method BindMethod, creds Credentials, skipVerify ...bool) error {
	var err error

	if len(skipVerify) > 0 {
		c.skipVerify = skipVerify[0]
	}
	c.url = url
	switch method {
	case MethodBindAnonymous:
		err = c.BindAnonymous(creds)

	case MethodBindDomain:
		err = c.BindDomain(creds)

	case MethodBindDomainPTH:
		err = c.BindDomainPTH(creds)

	case MethodBindGSSAPI:
		err = c.BindGSSAPI(creds)

	case MethodBindPassword:
		err = c.BindPassword(creds)

	default:
		return errors.New("invalid bind method")
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *LDAPConn) Delete(dn string) error {
	delReq := ldap.NewDelRequest(dn, nil)
	return c.lconn.Del(delReq)
}

func (c *LDAPConn) Close() error {
	if c.gssClient != nil {
		c.gssClient.Close()
	}
	if c.lconn != nil {
		c.lconn.Close()
	}
	return nil
}

func (c *LDAPConn) Query(basedn string,
	searchscope int,
	filter string,
	attributes []string) (Results, error) {
	if c.lconn == nil {
		return nil, errors.New("you must bind before searching")
	}
	var ldapControls []ldap.Control

	for _, attribute := range attributes {
		if control, ok := controlStringLookup[strings.ToLower(attribute)]; ok {
			ldapControls = append(ldapControls, control)
		}

	}

	if Debug {
		if c.username != "" {
			log.Printf(
				"[+] ldapsearch -H %s -D %s -W -b %s -o tls_reqcert=allow '%s' %s\n",
				c.url,
				c.username,
				basedn,
				filter,
				strings.Join(attributes, " "),
			)
		} else {
			log.Printf(
				"[+] ldapsearch -H %s -b %s -o tls_reqcert=allow '%s' %s\n",
				c.url,
				basedn,
				filter,
				strings.Join(attributes, " "),
			)
		}
	}
	var err error
	var result *ldap.SearchResult
	searchReq := ldap.NewSearchRequest(
		basedn,
		searchscope,
		0,
		0,
		0,
		false,
		filter,
		attributes,
		ldapControls,
	)

	result, err = c.lconn.Search(searchReq)
	if err != nil {
		return nil, err
	}

	var results Results

	if len(result.Entries) == 0 {
		return nil, errors.New(
			"no entries found",
		) // custom error result not found
	}

	for _, entry := range result.Entries {
		results.Add(*NewResultFromLDAP(entry))

	}

	return results, nil
}

func (c *LDAPConn) bindSetup() error {
	var err error

	// If proxy is configured, use SOCKS5 dialer
	if c.proxyURL != "" {
		// Parse LDAP URL to get host
		u, err := url.Parse(c.url)
		if err != nil {
			return err
		}

		// Parse proxy URL to get host:port
		proxyURL, err := url.Parse(c.proxyURL)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %w", err)
		}

		proxyAddr := proxyURL.Host
		if proxyAddr == "" {
			// If no scheme, assume it's already host:port
			proxyAddr = c.proxyURL
		}

		// Create SOCKS5 dialer
		proxyDialer, err := proxy.SOCKS5("tcp",
			proxyAddr,
			nil, // no auth
			proxy.Direct)
		if err != nil {
			return err
		}

		// Dial through proxy - add default port if missing
		ldapAddr := u.Host
		if !strings.Contains(ldapAddr, ":") {
			if strings.HasPrefix(c.url, "ldaps:") {
				ldapAddr += ":636"
			} else {
				ldapAddr += ":389"
			}
		}

		conn, err := proxyDialer.Dial("tcp", ldapAddr)
		if err != nil {
			return err
		}

		// Wrap with TLS if using LDAPS
		if strings.HasPrefix(c.url, "ldaps:") {
			tlsConn := tls.Client(conn, &tls.Config{
				InsecureSkipVerify: c.skipVerify,
				ServerName:         u.Hostname(),
			})
			conn = tlsConn
		}

		c.lconn = ldap.NewConn(
			conn,
			strings.HasPrefix(c.url, "ldaps:"),
		)
		c.lconn.Start()
	} else {
		// Original direct connection code
		if strings.HasPrefix(c.url, "ldaps:") {
			// look into other dialer
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
	}

	if LDAPDebug {
		c.lconn.Debug = true
	}

	return nil
}

// BindAnonymous will attempt to bind to the specified URL with an optional username.
func (c *LDAPConn) BindAnonymous(cred Credentials) error {
	c.username = cred.Username
	var err error

	err = c.bindSetup()
	if err != nil {
		return err
	}

	err = c.lconn.UnauthenticatedBind(c.username)
	if err != nil {
		return err
	}

	return nil
}

// BindDomain will attempt to bind to the specified URL with a username, password and domain.
func (c *LDAPConn) BindDomain(cred Credentials) error {
	c.username = cred.Username
	var err error

	err = c.bindSetup()
	if err != nil {
		return err
	}

	err = c.lconn.NTLMBind(cred.Domain, c.username, cred.Password)
	if err != nil {
		return err
	}

	return nil
}

// BindDomainPTH will attempt to bind to the specified URL with a username, password hash and domain.
func (c *LDAPConn) BindDomainPTH(cred Credentials) error {
	c.username = cred.Username
	var err error

	err = c.bindSetup()
	if err != nil {
		return err
	}

	err = c.lconn.NTLMBindWithHash(cred.Domain, c.username, cred.Hash)
	if err != nil {
		return err
	}

	return nil
}

func (c *LDAPConn) BindGSSAPI(cred Credentials) error {
	// GSSAPI Implementation
	c.username = cred.Username
	var spn string = "ldap/" + cred.DC
	var err error

	c.gssClient, err = gssapi.NewClientWithPassword(
		cred.Username,                // Kerberos principal name
		strings.ToUpper(cred.Domain), // Kerberos realm
		cred.Password,                // Kerberos password
		"/etc/krb5.conf",             // krb5 configuration file path
		client.DisablePAFXFAST(
			true,
		), // Optional: disable FAST if your realm needs it
	)
	if err != nil {
		return err
	}

	err = c.bindSetup()
	if err != nil {
		return err
	}

	err = c.lconn.GSSAPIBindRequestWithAPOptions(
		c.gssClient,
		&ldap.GSSAPIBindRequest{
			ServicePrincipalName: spn,
			AuthZID:              "",
		},
		[]int{flags.APOptionMutualRequired},
	)
	if err != nil {
		return err
	}

	return nil
}

// BindPassword will attempt a simple bind to the specified  URL with supplied username and password
func (c *LDAPConn) BindPassword(cred Credentials) error {
	c.username = cred.Username
	var err error

	err = c.bindSetup()
	if err != nil {
		return err
	}

	err = c.lconn.Bind(cred.Username, cred.Password)
	if err != nil {
		return err
	}

	return nil
}
func (c *LDAPConn) SetProxy(proxyURL string) {
	c.proxyURL = proxyURL
}

func (c *LDAPConn) WhoAmI() (string, error) {
	if c.lconn == nil {
		return "", errors.New("you must bind before searching")
	}
	result, err := c.lconn.WhoAmI(nil)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", *result), nil
}
