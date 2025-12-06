package ldaptickler

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/huner2/go-sddlparse"

	// Todo replace below library, go-sddlparse is much better
	winsddlconverter "github.com/ineffectivecoder/win-sddl-converter"
	"github.com/jcmturner/gokrb5/iana/flags"
	"github.com/jcmturner/gokrb5/v8/client"
	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
)

// BindMethod TODO WHAT IS THIS?!
type BindMethod int

type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	BufferOffset  uint32
}
type RPCUnicodeString struct {
	ReferentID    uint32
	Length        uint16
	MaximumLength uint16
	BufferOffset  uint32
}

type MSDSManagedPasswordBlob struct {
	Version                uint32
	Length                 uint32
	CurrentPasswordOffset  uint32
	PreviousPasswordOffset uint16
	QueryPasswordOffset    uint16
	Buffer                 []byte // raw payload after header
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

// This will reveal creds in plain text, yay
var LDAPDebug bool
var reSDDL *regexp.Regexp = regexp.MustCompile(`(\([^\)]+\))`)

// Conn gives us a structure named lconn linked to *ldap.Conn
type Conn struct {
	lconn      *ldap.Conn
	gssClient  *gssapi.Client
	baseDN     string
	skipVerify bool
	url        string
}

// New TODO great note Chris
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
	if LDAPDebug {
		c.lconn.Debug = true
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

func (c *Conn) BindGSSAPI(domain string, username string, password string, spn string) error {
	// GSSAPI Implementation
	var err error
	c.gssClient, err = gssapi.NewClientWithPassword(
		username,                     // Kerberos principal name
		strings.ToUpper(domain),      // Kerberos realm
		password,                     // Kerberos password
		"/etc/krb5.conf",             // krb5 configuration file path
		client.DisablePAFXFAST(true), // Optional: disable FAST if your realm needs it
	)
	if err != nil {
		return err
	}

	err = c.bindSetup()
	if err != nil {
		return err
	}
	err = c.lconn.GSSAPIBindRequestWithAPOptions(c.gssClient, &ldap.GSSAPIBindRequest{
		ServicePrincipalName: spn,
		AuthZID:              "",
	},
		[]int{flags.APOptionMutualRequired})
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

// AddConstrainedDelegation modifies msds-allowedtodelegateto to configured constrained delegation for specified spn
func (c *Conn) AddConstrainedDelegation(username string, spn string) error {
	var delegationres string
	filter := "(samaccountname=" + username + ")"
	attributes := []string{"msDS-AllowedToDelegateTo"}
	searchscope := 2
	var err error
	var results []map[string][]string
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		if !strings.Contains(err.Error(), "no attributes") {
			return err
		}
	}
	if len(results[0]["msDS-AllowedToDelegateTo"]) > 0 {
		delegationres = results[0]["msDS-AllowedToDelegateTo"][0]
	}
	delegationres = strings.TrimSpace(fmt.Sprintf("%s %s", delegationres, spn))
	enableReq := ldap.NewModifyRequest(results[0]["DN"][0], []ldap.Control{})
	enableReq.Replace("msDS-AllowedToDelegateTo", []string{delegationres})
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

// AddMachineAccountLowPriv will attempt to add a machine account with the supplied details as a low privilege user
func (c *Conn) AddMachineAccountLowPriv(machinename string, machinepass string, domain string) error {
	// AD requires machine SAM to end in $
	sam := strings.TrimSpace(machinename)
	if !strings.HasSuffix(sam, "$") {
		sam += "$"
	}
	// CN must not include the trailing $
	cn := strings.TrimSuffix(sam, "$")
	// Format unicodePwd: UTF-16LE, quoted
	//encoded, _ := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().String(machinepass)
	quoted := fmt.Sprintf("\"%s\"", machinepass)
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	encodedPwd, err := utf16.NewEncoder().String(quoted)
	if err != nil {
		return err
	}
	dn := fmt.Sprintf("CN=%s,CN=Computers,%s", cn, c.baseDN)
	addReq := ldap.NewAddRequest(dn, nil)
	// Required object classes for low-priv creation
	addReq.Attribute("objectClass", []string{
		"top",
		"computer",
	})
	// DOES THE ORDER MATTER? Aligning with Impacket addcomputer.py
	fqdn := fmt.Sprintf("%s.%s", cn, domain)
	addReq.Attribute("dNSHostName", []string{fqdn})
	addReq.Attribute("userAccountControl", []string{"4096"}) // WORKSTATION_TRUST_ACCOUNT
	addReq.Attribute("servicePrincipalName", []string{
		"HOST/" + strings.ToLower(cn),
		"HOST/" + strings.ToLower(fqdn),
		"RestrictedKrbHost/" + strings.ToLower(cn),
		"RestrictedKrbHost/" + strings.ToLower(fqdn),
	})
	addReq.Attribute("sAMAccountName", []string{sam})
	addReq.Attribute("unicodePwd", []string{encodedPwd})
	/*addReq.Attribute("operatingSystem", []string{"Windows"})
	addReq.Attribute("operatingSystemVersion", []string{"11.0"})
	addReq.Attribute("operatingSystemServicePack", []string{"Service Pack 0"})*/

	return c.lconn.Add(addReq)
}

// AddResourceBasedConstrainedDelegation will attempt to add RBCD permissions from delegatingComputer to targetmachinename
func (c *Conn) AddResourceBasedConstrainedDelegation(targetmachinename string, delegatingComputer ...string) error {
	filter := "(samaccountname=" + delegatingComputer[0] + ")"
	attributes := []string{"objectSid"}
	searchscope := 2
	var err error
	var results []map[string][]string
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}

	// Getting object sid
	if len(results[0]["objectSid"]) == 0 {
		return fmt.Errorf("no objectSid found for %s", delegatingComputer[0])

	}
	delegatingComputerSID := results[0]["objectSid"][0]

	filter = "(samaccountname=" + targetmachinename + ")"
	attributes = []string{"msDS-AllowedToActOnBehalfOfOtherIdentity"}
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}

	dn := results[0]["DN"][0]
	if !strings.Contains(strings.ToLower(dn), "cn=computers") {
		return fmt.Errorf("this object is not a computer, go away")
	}

	var allowed string

	// Getting msDS-AllowedToActOnBehalfOfOtherIdentity
	if len(results[0]["msDS-AllowedToActOnBehalfOfOtherIdentity"]) > 0 {
		allowed = results[0]["msDS-AllowedToActOnBehalfOfOtherIdentity"][0]
	}
	// RBCD setting
	sddl, err := winsddlconverter.ParseSDDL(allowed)

	if err != nil {
		return err
	}
	if sddl.Owner == "" {
		sddl.Owner = "BA"
	}
	if sddl.Group == "" {
		sddl.Group = "BA"
	}
	if sddl.DiscretionaryAcl == nil {
		sddl.DiscretionaryAcl = &winsddlconverter.Acl{AclRevision: 2, Aces: []winsddlconverter.Ace{}}
	}
	for _, ace := range sddl.DiscretionaryAcl.Aces {
		if delegatingComputerSID == ace.Sid {
			return fmt.Errorf("delegating computer already has RBCD permissions on target computer")
		}
	}
	ace := winsddlconverter.Ace{
		AceType: winsddlconverter.ACCESS_ALLOWED_ACE_TYPE, Sid: delegatingComputerSID,
		AccessMask: winsddlconverter.AccessMaskDetail{Mask: 0xF01FF, Flags: []string{"SD", "RC", "WD", "WO"}, HasUnknown: true},
	}
	sddl.DiscretionaryAcl.Aces = append(sddl.DiscretionaryAcl.Aces, ace)
	var b []byte
	if b, err = sddl.ToBinary(); err != nil {
		return err
	}

	enableReq := ldap.NewModifyRequest(dn, []ldap.Control{})
	enableReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(b)})
	return c.lconn.Modify(enableReq)
}

// TODO Add filter elsewhere
func (c *Conn) AddServicePrincipalName(username string, spn string) error {
	// Escape username for LDAP filter
	filter := fmt.Sprintf("(samaccountname=%s)", ldap.EscapeFilter(username))
	attributes := []string{"servicePrincipalName"}

	// Search for the user
	results, err := c.getAllResults(2, filter, attributes)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("user %s not found", username)
	}

	userDN := results[0]["DN"][0]

	existingSPNs := results[0]["servicePrincipalName"]

	// Check if SPN already exists
	for _, s := range strings.Fields(spn) {
		//if !slices.Contains(existingSPNs, s) {
		existingSPNs = append(existingSPNs, s)
		//}
	}

	// Prepare LDAP modify request to add SPN
	modReq := ldap.NewModifyRequest(userDN, []ldap.Control{})
	modReq.Replace("servicePrincipalName", existingSPNs)

	// Execute modification
	return c.lconn.Modify(modReq)
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

// AddUnconstrainedDelegation will modify the useraccountcontrol field to enable unconstrained delegation
func (c *Conn) AddUnconstrainedDelegation(username string) error {
	// THIS WORKS AGAIN!
	//Machine accounts require $ you dummy.
	//UAC output is a bit mask which can be deciphered here: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
	var err error
	var results []map[string][]string
	var uacstr string
	filter := "(samaccountname=" + username + ")"
	attributes := []string{"userAccountControl"}
	searchscope := 2
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	if len(results[0]["userAccountControl"]) > 0 {
		uacstr = results[0]["userAccountControl"][0]
	}

	uac, err := flagset(uacstr, UACTrustedForDelegation)
	if err != nil {
		return err
	}

	// Get value for UAC, and then apply value to bitmask
	enableReq := ldap.NewModifyRequest(results[0]["DN"][0], []ldap.Control{})
	enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(enableReq)
}

// Close closes the LDAP connection
func (c *Conn) Close() error {
	if c.gssClient != nil {
		c.gssClient.Close()
	}
	if c.lconn != nil {
		c.lconn.Close()
	}
	return nil
}

func decodeGUID(guidBytes []byte) string {
	if len(guidBytes) != 16 {
		return fmt.Sprintf("Invalid GUID: %0x", guidBytes)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		// first 4 bytes (little-endian)
		uint32(guidBytes[3])<<24|uint32(guidBytes[2])<<16|uint32(guidBytes[1])<<8|uint32(guidBytes[0]),
		// next 2 bytes (little-endian)
		uint16(guidBytes[5])<<8|uint16(guidBytes[4]),
		// next 2 bytes (little-endian)
		uint16(guidBytes[7])<<8|uint16(guidBytes[6]),
		// next 2 bytes (big-endian)
		guidBytes[8], guidBytes[9],
		// last 6 bytes (big-endian)
		guidBytes[10], guidBytes[11], guidBytes[12], guidBytes[13], guidBytes[14], guidBytes[15],
	)
}

func decodeSID(sidBytes []byte) (string, error) {
	// 0 = revision, 1 = sub-authority count, 2-7 identifier authority, each sub authority is 4 bytes
	// Check # of bytes to ensure proper SID
	if len(sidBytes) < 8 {
		return "", fmt.Errorf("invalid SID length")
	}
	revision := sidBytes[0]
	subAuthCount := int(sidBytes[1])
	identifierAuthority := uint64(sidBytes[2])<<40 |
		uint64(sidBytes[3])<<32 |
		uint64(sidBytes[4])<<24 |
		uint64(sidBytes[5])<<16 |
		uint64(sidBytes[6])<<8 |
		uint64(sidBytes[7])

	if len(sidBytes) < 8+subAuthCount*4 {
		return "", fmt.Errorf("invalid SID length for sub-authorities")
	}
	subAuthorities := make([]uint32, subAuthCount)
	for i := 0; i < subAuthCount; i++ {
		start := 8 + i*4
		subAuthorities[i] = binary.LittleEndian.Uint32(sidBytes[start : start+4])
	}

	sidStr := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)
	for _, sa := range subAuthorities {
		sidStr += fmt.Sprintf("-%d", sa)
	}
	return sidStr, nil

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

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8?redirectedfrom=MSDN
func byteReader(br *bytes.Reader, length int) ([]byte, error) {
	b := make([]byte, length)
	n, err := br.Read(b)
	if err != nil {
		return nil, err
	}
	if n != length {
		return nil, fmt.Errorf("could not read dnsRecord")
	}
	return b, nil
}

// ParseMSDSManagedPasswordBlob parses the binary blob from msDS-ManagedPassword attribute
func ParseMSDSManagedPasswordBlob(blob []byte) (*MSDSManagedPasswordBlob, error) {
	if len(blob) < 16 {
		return nil, fmt.Errorf("blob too short: expected at least 16 bytes, got %d", len(blob))
	}

	br := bytes.NewReader(blob)

	// Read header fields
	header := make([]byte, 16)
	if _, err := br.Read(header); err != nil {
		return nil, err
	}

	result := &MSDSManagedPasswordBlob{
		Version:                binary.LittleEndian.Uint32(header[0:4]),
		Length:                 binary.LittleEndian.Uint32(header[4:8]),
		CurrentPasswordOffset:  binary.LittleEndian.Uint32(header[8:12]),
		PreviousPasswordOffset: binary.LittleEndian.Uint16(header[12:14]),
		QueryPasswordOffset:    binary.LittleEndian.Uint16(header[14:16]),
	}

	// Read remaining buffer
	remaining := make([]byte, len(blob)-16)
	if _, err := br.Read(remaining); err != nil && err.Error() != "EOF" {
		return nil, err
	}
	result.Buffer = remaining

	return result, nil
}

// GetCurrentPassword extracts the current password from the blob
func (m *MSDSManagedPasswordBlob) GetCurrentPassword() ([]byte, error) {
	if m.CurrentPasswordOffset == 0 {
		return nil, fmt.Errorf("current password offset is 0")
	}

	// Password offset is relative to start of buffer
	offset := int(m.CurrentPasswordOffset) - 16 // subtract header size since Buffer starts after header
	if offset < 0 || offset >= len(m.Buffer) {
		return nil, fmt.Errorf("invalid current password offset: %d", m.CurrentPasswordOffset)
	}

	// Read 256 bytes (standard password length for gMSA)
	end := offset + 256
	if end > len(m.Buffer) {
		return nil, fmt.Errorf("password extends beyond buffer")
	}

	return m.Buffer[offset : offset+256], nil
}

// GetCurrentPasswordNTLMHash computes the NTLM hash of the current password
func (m *MSDSManagedPasswordBlob) GetCurrentPasswordNTLMHash() (string, error) {
	pwd, err := m.GetCurrentPassword()
	if err != nil {
		return "", err
	}

	h := md4.New()
	h.Write(pwd)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dnsrpcnameToString(b []byte) (string, error) {
	br := bytes.NewReader(b[1:]) // skip first byte
	b, err := byteReader(br, 1)
	if err != nil {
		return "", err
	}
	sections := int(b[0])
	data := ""
	for range sections {
		b, err = byteReader(br, 1)
		if err != nil {
			return "", err
		}
		b, err = byteReader(br, int(b[0]))
		if err != nil {
			return "", err
		}
		if data != "" {
			data += "."
		}
		data += string(b)
	}
	return data, nil
}

func (c *Conn) getAllResults(
	searchscope int, filter string, attributes []string, baseDN ...string,
) ([]map[string][]string, error) {
	var results []map[string][]string
	var data string
	var ldapControls []ldap.Control
	if len(baseDN) == 0 {
		baseDN = []string{c.baseDN}
	}

	// Minimal ASN.1: Sequence {INTEGER 0x07 }
	if slices.Contains(attributes, "nTSecurityDescriptor") {
		ldapControls = []ldap.Control{
			&ldap.ControlString{
				ControlType:  "1.2.840.113556.1.4.801", // LDAP_SERVER_SD_FLAGS_OID
				Criticality:  true,
				ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x07}),
			},
		}
	}
	if slices.Contains(attributes, "msDS-ManagedPassword") {
		ldapControls = append(ldapControls,
			&ldap.ControlString{
				ControlType:  "1.2.840.113556.1.4.2064",                    // PolicyHints OID
				Criticality:  false,                                        // must be non-critical
				ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x01}), // raw BER: SEQUENCE(INT=1)
			},
		)
	}

	result, err := c.ldapSearch(baseDN[0], searchscope, filter, attributes, ldapControls...)
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("no entries found") // custom error result not found
	}
	for i, entry := range result.Entries {
		results = append(results, map[string][]string{})
		results[i]["DN"] = []string{entry.DN}
		for _, attribute := range entry.Attributes {
			switch strings.ToLower(attribute.Name) {
			case "dnsrecord":
				values := []string{}
				for _, v := range attribute.ByteValues {
					br := bytes.NewReader(v)
					// reading size
					b, err := byteReader(br, 2)
					if err != nil {
						return nil, err
					}
					datalength, n := binary.Uvarint(b)
					if n == 0 {
						return nil, fmt.Errorf("could not read record type")
					}
					// reading in rectype
					b, err = byteReader(br, 2)
					if err != nil {
						return nil, err
					}
					rectype := binary.LittleEndian.Uint64(append(b, []byte{0, 0, 0, 0, 0, 0}...))
					if _, ok := recTypes[rectype]; !ok {
						values = append(values, fmt.Sprintf("Unknown record type %d", rectype))
						continue
					}
					// read and skip version(1 byte), rank(1 byte) , flags (2 byte), serial(4 byte)
					_, err = byteReader(br, 8)
					if err != nil {
						return nil, err
					}
					// reading in TTL
					b, err = byteReader(br, 4)
					if err != nil {
						return nil, err
					}
					ttl := binary.BigEndian.Uint64(append([]byte{0, 0, 0, 0}, b...))
					// skipping reserved(4 bytes) and timestamp(4 bytes) = 8
					_, err = byteReader(br, 8)
					if err != nil {
						return nil, err
					}
					// reading in Data(variable length, fun!)
					b, err = byteReader(br, int(datalength))
					if err != nil {
						return nil, err
					}
					switch recTypes[rectype] {
					case "A":
						data = net.IP(b).String()
					case "AAAA":
						data = net.IP(b).String()
					case "TXT", "HINFO", "ISDN", "X25", "LOC":
						data = string(b)
					case "CNAME", "NS", "PTR", "DNAME", "MB", "MG", "MR", "MD", "MF":
						data, err = dnsrpcnameToString(b)
						if err != nil {
							return nil, err
						}

					case "SRV":
						// Skipping priority and weight, 2 bytes each
						br2 := bytes.NewReader(b[4:])
						// read 2 bytes for port
						b, err = byteReader(br2, 2)
						if err != nil {
							return nil, err
						}
						port := binary.BigEndian.Uint16(b)
						b = make([]byte, br2.Len())
						_, err := br2.Read(b)
						if err != nil {
							return nil, err
						}
						data, err = dnsrpcnameToString(b)
						if err != nil {
							return nil, err
						}
						data = fmt.Sprintf("%s:%d", data, port)
					case "SOA":
						// Skipping serial, refresh, retry, expire, minimum (4 bytes each = 20 bytes )
						data, err = dnsrpcnameToString(b[20:])
						if err != nil {
							return nil, err
						}

					default:
						data = "Unsupported:" + hex.EncodeToString(b)
					}
					_ = ttl
					val := fmt.Sprintf("%s(%s)", recTypes[rectype], data)
					values = append(values, val)
				}
				results[i][attribute.Name] = values
			case "objectguid":
				values := []string{}
				for _, v := range attribute.ByteValues {

					values = append(values, decodeGUID(v))
				}
				results[i][attribute.Name] = values
			case "objectsid":
				values := []string{}
				for _, v := range attribute.ByteValues {
					v, _ := decodeSID(v)
					values = append(values, v)
				}
				results[i][attribute.Name] = values
			case "msds-allowedtoactonbehalfofotheridentity":
				values := []string{}
				for _, v := range attribute.ByteValues {

					sddl, err := sddlparse.SDDLFromBinary(v)
					if err != nil {
						return nil, err
					}
					value := ""

					for _, ace := range sddl.DACL {

						value += ace.String()

					}
					values = append(values, reSDDL.ReplaceAllString(value+"\n    ", "\n      $1"))
				}
				results[i][attribute.Name] = values
			case "msds-groupmsamembership":
				values := []string{}
				for _, v := range attribute.ByteValues {

					sddl, err := sddlparse.SDDLFromBinary(v)
					if err != nil {
						return nil, err
					}
					value := ""

					for _, ace := range sddl.DACL {

						value += ace.String()

					}
					values = append(values, reSDDL.ReplaceAllString(value+"\n    ", "\n      $1"))
				}
				results[i][attribute.Name] = values

				// WELL CRAP, sounds like you have to pass another control option to pull this.
			case "msds-managedpassword":
				values := []string{}

				for _, v := range attribute.ByteValues {
					blob, err := ParseMSDSManagedPasswordBlob(v)
					if err != nil {
						values = append(values, fmt.Sprintf("Error parsing blob: %v", err))
						continue
					}

					ntlmHash, err := blob.GetCurrentPasswordNTLMHash()
					if err != nil {
						values = append(values, fmt.Sprintf("Error computing NTLM hash: %v", err))
						continue
					}

					values = append(values, fmt.Sprintf("NTLM Hash: %s", ntlmHash))
				}

				results[i][attribute.Name] = values

			case "ntsecuritydescriptor":
				values := []string{}
				for _, v := range attribute.ByteValues {

					sddl, err := sddlparse.SDDLFromBinary(v)
					if err != nil {
						return nil, err
					}
					value := ""
					writemasks := sddlparse.ACCESS_MASK_GENERIC_ALL | sddlparse.ACCESS_MASK_GENERIC_WRITE | sddlparse.ACCESS_MASK_WRITE_OWNER | sddlparse.ACCESS_MASK_WRITE_DACL
					for _, ace := range sddl.DACL {
						if ace.AccessMask&writemasks > 0 {
							value += ace.String()
						}
					}
					values = append(values, reSDDL.ReplaceAllString(value+"\n    ", "\n      $1"))
				}
				results[i][attribute.Name] = values

			default:
				results[i][attribute.Name] = attribute.Values
			}
		}
	}
	return results, nil
}

// Get the DN of a specific user
func (c *Conn) getUserDN(username string) (string, error) {
	filter := fmt.Sprintf("(&(objectClass=person)(sAMAccountName=%s))", username)
	attributes := []string{"distinguishedName"}
	searchscope := 2

	results, err := c.getAllResults(searchscope, filter, attributes, c.baseDN)
	if err != nil {
		return "", err
	}

	if len(results) == 0 {
		return "", fmt.Errorf("user %s not found", username)
	}

	return results[0]["distinguishedName"][0], nil
}

// GetWhoAmI will query the LDAP server for who we currently are authenticated as
func (c *Conn) GetWhoAmI() (*ldap.WhoAmIResult, error) {
	result, err := c.lconn.WhoAmI(nil)
	if err != nil {
		return nil, err
	}
	return result, err
}

func (c *Conn) ldapSearch(basedn string, searchscope int, filter string, attributes []string, controls ...ldap.Control) (*ldap.SearchResult, error) {
	if c.lconn == nil {
		return nil, fmt.Errorf("you must bind before searching")
	}
	var err error
	var result *ldap.SearchResult
	searchReq := ldap.NewSearchRequest(basedn, searchscope, 0, 0, 0, false, filter, attributes, controls)
	result, err = c.lconn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	return result, err
}

// LDAPSearch will search the directory by a supplied searchscope, filter and attributes
func (c *Conn) LDAPSearch(searchscope int, filter string, attributes []string, baseDN ...string) error {
	var keys []string
	var err error
	var results []map[string][]string
	results, err = c.getAllResults(searchscope, filter, attributes, baseDN...)
	if err != nil {
		return err
	}
	for _, result := range results {
		fmt.Printf("  DN: %s\n", result["DN"][0])
		keys = []string{}
		for key := range result {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			values := result[key]
			if key == "DN" {
				continue // Skip DN key as it is already printed
			}
			if len(values) == 0 {
				fmt.Printf("    %s: No values found\n", key)
				continue
			}
			fmt.Printf("    %s: %v\n", key, values)
		}
	}
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

// ListDNS will search the directory for all DNS records
func (c *Conn) ListDNS() error {
	filter := "(&(objectClass=dnsNode)(dnsRecord=*))"
	attributes := []string{"name", "dnsRecord", "dnsHostName"}
	searchscope := 2
	var err error = c.LDAPSearch(searchscope, filter, attributes, "DC=DomainDnsZones,"+c.baseDN)
	if err != nil {
		return err
	}
	return nil
}

// ListGMSAaccounts will search the directory for all Group Managed Service Accounts and display the credential if you have p
func (c *Conn) ListGMSAaccounts() error {
	filter := "(&(objectClass=msDS-GroupManagedServiceAccount)(samaccountname=*))"
	attributes := []string{"samaccountname", "msDS-GroupMSAMembership", "msds-ManagedPasswordInterval", "msDS-ManagedPassword"}
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

// ListMachineCreationDACL will identify the DACL on the Computers container
func (c *Conn) ListMachineCreationDACL() error {
	filter := "(objectClass=domainDNS)"
	attributes := []string{"nTSecurityDescriptor"}
	searchscope := 2
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
	var err error

	filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	attributes := []string{"samaccountname", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
	searchscope := 2
	err = c.LDAPSearch(searchscope, filter, attributes)
	if err != nil {
		return err
	}

	return nil
}

// ListSchema will list the schema of the directory
func (c *Conn) ListSchema() error {
	filter := "(objectClass=*)"
	attributes := []string{}
	searchscope := 0
	var err error = c.LDAPSearch(searchscope, filter, attributes, "cn=Schema,cn=Configuration,"+c.baseDN)
	if err != nil {
		return err
	}
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

// ListUserLoginScripts lists all scripts configured for user accounts, does not include GPO
func (c *Conn) ListLoginScripts() error {
	filter := "(scriptPath=*)"
	attributes := []string{"sAMAccountName", "scriptPath", "userAccountControl"}
	searchscope := 2
	return c.LDAPSearch(searchscope, filter, attributes)
}

// RemoveConstrainedDelegation modifies msds-allowedtodelegateto to remove configuration of specific spns or all of them
func (c *Conn) RemoveConstrainedDelegation(username string, spn string) error {
	var delegationres string
	filter := "(samaccountname=" + username + ")"
	attributes := []string{"msDS-AllowedToDelegateTo"}
	searchscope := 2
	var err error
	var results []map[string][]string
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	if len(results[0]["msDS-AllowedToDelegateTo"]) > 0 {
		delegationres = results[0]["msDS-AllowedToDelegateTo"][0]
	}
	spns := strings.Fields(delegationres)
	var updatedSPNs []string
	if strings.ToLower(spn) == "all" {
		updatedSPNs = []string{}
	} else {
		for _, h := range spns {
			if !strings.EqualFold(h, spn) {
				//if strings.ToLower(h) != strings.ToLower(spn) { Linter says dont do this.
				updatedSPNs = append(updatedSPNs, h)
			}
		}
	}
	// fmt.Printf("%s\n", delegationresstr)
	enableReq := ldap.NewModifyRequest(results[0]["DN"][0], []ldap.Control{})
	enableReq.Replace("msDS-AllowedToDelegateTo", updatedSPNs)
	return c.lconn.Modify(enableReq)
}

// RemoveLoginScript removes login script from given user
func (c *Conn) RemoveLoginScript(username string) error {
	// First, get the user's DN
	userDN, err := c.getUserDN(username)
	if err != nil {
		return err
	}

	// Create the LDAP modify request
	modifyReq := ldap.NewModifyRequest(userDN, nil)

	// Delete the scriptPath attribute (removes any existing value)
	modifyReq.Delete("scriptPath", nil)

	return c.lconn.Modify(modifyReq)
}

func (c *Conn) RemoveResourceBasedConstrainedDelegation(targetmachinename string) error {
	filter := "(samaccountname=" + targetmachinename + ")"
	attributes := []string{"msDS-AllowedToActOnBehalfOfOtherIdentity"}
	searchscope := 2
	results, err := c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}

	dn := results[0]["DN"][0]
	enableReq := ldap.NewModifyRequest(dn, []ldap.Control{})
	enableReq.Delete("msDS-AllowedToActOnBehalfOfOtherIdentity", nil)
	return c.lconn.Modify(enableReq)
}

func (c *Conn) RemoveSPNs(username string, spn string) error {
	var spnValues string
	filter := "(samaccountname=" + username + ")"
	attributes := []string{"servicePrincipalName"}
	searchscope := 2

	results, err := c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("user %s not found", username)
	}

	if len(results[0]["servicePrincipalName"]) > 0 {
		spnValues = results[0]["servicePrincipalName"][0]
	}

	existingSPNs := strings.Fields(strings.ToLower(spnValues))
	deleteSPNs := strings.Fields(strings.ToLower(spn))
	var updatedSPNs []string

	if strings.ToLower(spn) == "all" {
		updatedSPNs = []string{}
	} else {
		for _, val := range existingSPNs {
			if !slices.Contains(deleteSPNs, val) {
				updatedSPNs = append(updatedSPNs, val)
			}
		}
	}

	modReq := ldap.NewModifyRequest(results[0]["DN"][0], []ldap.Control{})
	modReq.Replace("servicePrincipalName", updatedSPNs)

	return c.lconn.Modify(modReq)
}

// RemoveUnconstrainedDelegation will modify the useraccountcontrol field to disable unconstrained delegation
func (c *Conn) RemoveUnconstrainedDelegation(username string) error {
	// Working again.
	var err error
	var results []map[string][]string
	var uacstr string
	filter := "(samaccountname=" + username + ")"
	attributes := []string{"userAccountControl"}
	searchscope := 2
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	if len(results[0]["userAccountControl"]) > 0 {
		uacstr = results[0]["userAccountControl"][0]
	}

	uac, err := flagunset(uacstr, UACTrustedForDelegation)
	if err != nil {
		return err
	}
	// Get value for UAC, and then apply value to bitmask
	enableReq := ldap.NewModifyRequest(results[0]["DN"][0], []ldap.Control{})
	enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(enableReq)
}

// SetDisableMachineAccount will modify the userAccountControl attribute to disable a machine account
func (c *Conn) SetDisableMachineAccount(username string) error {
	var err error
	var results []map[string][]string
	var uacstr string
	filter := "(&(objectClass=computer)(samaccountname=" + username + "))"
	attributes := []string{"useraccountcontrol"}
	searchscope := 2
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	if len(results[0]["userAccountControl"]) > 0 {
		uacstr = results[0]["userAccountControl"][0]
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
	var err error
	var results []map[string][]string
	var uacstr string
	filter := "(&(objectClass=computer)(samaccountname=" + username + "))"
	attributes := []string{"useraccountcontrol"}
	searchscope := 2
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	if len(results[0]["userAccountControl"]) > 0 {
		uacstr = results[0]["userAccountControl"][0]
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
	var err error
	var results []map[string][]string
	var uacstr string
	filter := "(&(objectClass=person)(samaccountname=" + username + "))"
	attributes := []string{"useraccountcontrol"}
	searchscope := 2
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	if len(results[0]["userAccountControl"]) > 0 {
		uacstr = results[0]["userAccountControl"][0]
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
	var err error
	var results []map[string][]string
	var uacstr string
	filter := "(&(objectClass=person)(samaccountname=" + username + "))"
	attributes := []string{"useraccountcontrol"}
	searchscope := 2
	results, err = c.getAllResults(searchscope, filter, attributes)
	if err != nil {
		return err
	}
	if len(results[0]["userAccountControl"]) > 0 {
		uacstr = results[0]["userAccountControl"][0]
	}

	uac, err := flagunset(uacstr, UACAccountDisable)
	if err != nil {
		return err
	}
	enableReq := ldap.NewModifyRequest("CN="+username+",CN=Users,"+c.baseDN, []ldap.Control{})
	enableReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return c.lconn.Modify(enableReq)
}

// SetLoginScript
func (c *Conn) SetLoginScript(username string, scriptname string) error {
	// Build the DN for the user
	userDN, err := c.getUserDN(username)
	if err != nil {
		return err
	}
	// Create the LDAP Modify request
	modifyReq := ldap.NewModifyRequest(userDN, []ldap.Control{})

	// Replace the existing scriptPath attribute (or create if missing)
	modifyReq.Replace("scriptPath", []string{scriptname})

	// Apply the modification
	return c.lconn.Modify(modifyReq)

}

// SetUserPassword will set a user account's password
func (c *Conn) SetUserPassword(username string, userpass string) error {
	passwordReq, err := c.createUnicodePasswordRequest(username, userpass)
	if err != nil {
		return err
	}
	return c.lconn.Modify(passwordReq)
}
