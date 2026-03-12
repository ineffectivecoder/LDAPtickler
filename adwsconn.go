package ldaptickler

import (
	"errors"
	"fmt"
	"strings"

	adws "github.com/Macmod/sopa"
)

type ADWSConn struct {
	proxyurl string
	url      string
	username string
	wsclient *adws.WSClient
}

func (c *ADWSConn) Add(dn string, attrs map[string][]string) error {
	return errors.New("Not Implemented")
}

func (c *ADWSConn) Bind(url string, method BindMethod, creds Credentials, _ ...bool) error {
	var cfg adws.Config
	var err error
	c.url = url
	if _, after, ok := strings.Cut(c.url, "://"); ok {
		c.url = after
	}

	switch method {
	case MethodBindAESKey:
		cfg, err = c.BindAESKey(creds)

	case MethodBindCCache:
		cfg, err = c.BindCCache(creds)

	case MethodBindCertKey:
		cfg, err = c.BindCertKey(creds)

	case MethodBindDomain:
		cfg, err = c.BindDomain(creds)

	case MethodBindDomainPTH:
		cfg, err = c.BindDomainPTH(creds)

	case MethodBindPFX:
		cfg, err = c.BindPFX(creds)

	default:
		return errors.New("invalid bind method")
	}
	if err != nil {
		return err
	}
	c.wsclient, err = adws.NewWSClient(cfg)
	if err != nil {
		return err
	}
	err = c.wsclient.Connect()
	if err != nil {
		return err
	}
	c.username = creds.Username

	return nil

}
func (c *ADWSConn) BindAESKey(creds Credentials) (adws.Config, error) {
	return adws.Config{}, errors.New("Not Implemented")
}

func (c *ADWSConn) BindCCache(creds Credentials) (adws.Config, error) {
	return adws.Config{}, errors.New("Not Implemented")
}

func (c *ADWSConn) BindCertKey(creds Credentials) (adws.Config, error) {
	return adws.Config{}, errors.New("Not Implemented")
}

func (c *ADWSConn) BindDomain(creds Credentials) (adws.Config, error) {
	return adws.Config{
		DCAddr:   c.url,
		Username: creds.Username,
		Password: creds.Password,
		Domain:   creds.Domain,
	}, nil
}

func (c *ADWSConn) BindDomainPTH(creds Credentials) (adws.Config, error) {
	return adws.Config{
		DCAddr:   c.url,
		Username: creds.Username,
		NTHash:   creds.Hash,
		Domain:   creds.Domain,
	}, nil
}

func (c *ADWSConn) BindPFX(creds Credentials) (adws.Config, error) {
	return adws.Config{}, errors.New("Not Implemented")
}

func (c *ADWSConn) Close() error {
	return errors.New("Not Implemented")
}

func (c *ADWSConn) Delete(dn string) error {
	return errors.New("Not Implemented")
}

func (c *ADWSConn) ModifyAdd(dn string, attr string, attrvals []string) error {
	return errors.New("Not Implemented")
}

func (c *ADWSConn) ModifyDelete(dn string, attr string) error {
	return errors.New("Not Implemented")
}

func (c *ADWSConn) ModifyReplace(dn string, attr string, attrvals []string) error {
	return errors.New("Not Implemented")

}

func (c *ADWSConn) Query(basedn string, searchscope int, filter string, attributes []string) (Results, error) {
	return nil, errors.New("Not Implemented")
}

func (c *ADWSConn) SetProxy(proxyURL string) {
	c.proxyurl = proxyURL
}

func (c *ADWSConn) WhoAmI() (string, error) {
	domain, err := c.wsclient.ADCAPGetADDomain()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("{u:%s\\%s}", domain.NetBIOSName, c.username), nil
}
