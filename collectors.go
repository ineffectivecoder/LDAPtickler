package ldaptickler

/*
Update 12/9/25 - This is more or less equal to the data being pulled with sharphound
LDAP Attribute Collection Strategy
====================================

This collector pulls all useful LDAP-accessible attributes from Active Directory objects.
We do not query attributes that require additional SMB/RPC calls or registry access (e.g., local group memberships).

USERS (25+ attributes):
  Identity: distinguishedName, sAMAccountName, userPrincipalName, objectSid, objectGUID
  Contact: displayName, givenName, sn, mail, mailNickname, telephoneNumber, mobile
  Memberships: memberOf, primaryGroupID
  Account: userAccountControl, accountExpires, scriptPath, homeDirectory, homeDrive
  Activity: lastLogon, lastLogonTimestamp, pwdLastSet, passwordExpired
  Delegation: servicePrincipalName, adminCount, userWorkstations
  Metadata: description, title, department, company, manager, whenCreated, whenChanged
  Security: nTSecurityDescriptor, msDS-UserPasswordExpiryTimeComputed

COMPUTERS (20+ attributes):
  Identity: distinguishedName, sAMAccountName, objectSid, objectGUID
  Network: dNSHostName, description
  OS: operatingSystem, operatingSystemVersion, operatingSystemServicePack
  Memberships: memberOf, primaryGroupID
  Account: userAccountControl, accountExpires
  Activity: lastLogon, lastLogonTimestamp, pwdLastSet
  Metadata: name, cn, whenCreated, whenChanged
  Security: nTSecurityDescriptor, msDS-Behavior-Version

GROUPS (14+ attributes):
  Identity: distinguishedName, cn, sAMAccountName, objectSid, objectGUID
  Membership: member, memberOf
  Type: groupType
  Metadata: description, mail, mailNickname, whenCreated, whenChanged
  Security: nTSecurityDescriptor

DOMAINS (12+ attributes):
  Identity: distinguishedName, objectSid, objectGUID, name, description
  Config: nETBIOSName, dc, msDS-Behavior-Version
  Metadata: whenCreated, whenChanged
  Security: nTSecurityDescriptor, objectVersion

OUS (10+ attributes):
  Identity: distinguishedName, objectGUID, name, description
  Policy: gPLink, gPOptions
  Metadata: whenCreated, whenChanged
  Security: nTSecurityDescriptor

GPOS (11+ attributes):
  Identity: distinguishedName, displayName, name, cn, objectGUID
  Config: gPCFunctionalityVersion, gPCFileSysPath
  Status: versionNumber
  Metadata: description, whenCreated, whenChanged

TRUSTS (9+ attributes):
  Identity: cn, distinguishedName, objectSid
  Trust: flatName, trustAttributes, trustDirection, trustType, trustPartner
  Metadata: whenCreated, whenChanged
*/

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BloodHound JSON schemas
type BHUser struct {
	ObjectID                string         `json:"ObjectIdentifier"`
	PrimaryGroupSID         *string        `json:"PrimaryGroupSID"`
	AllowedToDelegate       []string       `json:"AllowedToDelegate"`
	Properties              map[string]any `json:"Properties"`
	Aces                    []BHAce        `json:"Aces"`
	SPNTargets              []string       `json:"SPNTargets"`
	HasSIDHistory           []string       `json:"HasSIDHistory"`
	IsDeleted               bool           `json:"IsDeleted"`
	DomainSID               string         `json:"DomainSID"`
	UnconstrainedDelegation bool           `json:"UnconstrainedDelegation"`
	IsACLProtected          bool           `json:"IsACLProtected"`
	ContainedBy             *BHContainedBy `json:"ContainedBy"`
}

type BHContainedBy struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type BHComputer struct {
	ObjectID                string             `json:"ObjectIdentifier"`
	AllowedToAct            []string           `json:"AllowedToAct"`
	PrimaryGroupSID         *string            `json:"PrimaryGroupSID"`
	LocalAdmins             BHCollectionResult `json:"LocalAdmins"`
	PSRemoteUsers           BHCollectionResult `json:"PSRemoteUsers"`
	Properties              map[string]any     `json:"Properties"`
	RemoteDesktopUsers      BHCollectionResult `json:"RemoteDesktopUsers"`
	DcomUsers               BHCollectionResult `json:"DcomUsers"`
	AllowedToDelegate       []string           `json:"AllowedToDelegate"`
	Sessions                BHCollectionResult `json:"Sessions"`
	PrivilegedSessions      BHCollectionResult `json:"PrivilegedSessions"`
	RegistrySessions        BHCollectionResult `json:"RegistrySessions"`
	Aces                    []BHAce            `json:"Aces"`
	HasSIDHistory           []string           `json:"HasSIDHistory"`
	IsDeleted               bool               `json:"IsDeleted"`
	Status                  *string            `json:"Status"`
	IsDC                    bool               `json:"IsDC"`
	UnconstrainedDelegation bool               `json:"UnconstrainedDelegation"`
	DomainSID               string             `json:"DomainSID"`
	IsACLProtected          bool               `json:"IsACLProtected"`
	ContainedBy             *BHContainedBy     `json:"ContainedBy"`
}

type BHCollectionResult struct {
	Collected     bool     `json:"Collected"`
	FailureReason *string  `json:"FailureReason"`
	Results       []string `json:"Results"`
}

type BHGroup struct {
	ObjectID       string         `json:"ObjectIdentifier"`
	Properties     map[string]any `json:"Properties"`
	Members        []BHMember     `json:"Members"`
	Aces           []BHAce        `json:"Aces"`
	IsDeleted      bool           `json:"IsDeleted"`
	IsACLProtected bool           `json:"IsACLProtected"`
	ContainedBy    *BHContainedBy `json:"ContainedBy"`
	HasSIDHistory  []string       `json:"HasSIDHistory"`
}

type BHDomain struct {
	ObjectID             string         `json:"ObjectIdentifier"`
	Properties           map[string]any `json:"Properties"`
	Trusts               []string       `json:"Trusts"`
	Aces                 []BHAce        `json:"Aces"`
	Links                []string       `json:"Links"`
	ChildObjects         []string       `json:"ChildObjects"`
	GPOChanges           BHGPOChanges   `json:"GPOChanges"`
	IsDeleted            bool           `json:"IsDeleted"`
	ContainedBy          *BHContainedBy `json:"ContainedBy"`
	ForestRootIdentifier *string        `json:"ForestRootIdentifier"`
	InheritanceHashes    []any          `json:"InheritanceHashes"`
	IsACLProtected       bool           `json:"IsACLProtected"`
}

type BHGPOChanges struct {
	AffectedComputers  []string `json:"AffectedComputers"`
	DcomUsers          []string `json:"DcomUsers"`
	LocalAdmins        []string `json:"LocalAdmins"`
	PSRemoteUsers      []string `json:"PSRemoteUsers"`
	RemoteDesktopUsers []string `json:"RemoteDesktopUsers"`
}

type BHMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type BHCertTemplate struct {
	ObjectID       string         `json:"ObjectIdentifier"`
	Properties     map[string]any `json:"Properties"`
	Aces           []BHAce        `json:"Aces"`
	IsDeleted      bool           `json:"IsDeleted"`
	IsACLProtected bool           `json:"IsACLProtected"`
	ContainedBy    *BHContainedBy `json:"ContainedBy"`
}

type BHEnterpriseCA struct {
	ObjectID                string         `json:"ObjectIdentifier"`
	Properties              map[string]any `json:"Properties"`
	HostingComputer         *string        `json:"HostingComputer"`
	CARegistryData          any            `json:"CARegistryData"`
	EnabledCertTemplates    []BHMember     `json:"EnabledCertTemplates"`
	HttpEnrollmentEndpoints []string       `json:"HttpEnrollmentEndpoints"`
	IssuedBy                *string        `json:"IssuedBy"`
	Aces                    []BHAce        `json:"Aces"`
	IsDeleted               bool           `json:"IsDeleted"`
	IsACLProtected          bool           `json:"IsACLProtected"`
	ContainedBy             *BHContainedBy `json:"ContainedBy"`
}

type BHAIACA struct {
	ObjectID       string         `json:"ObjectIdentifier"`
	Properties     map[string]any `json:"Properties"`
	Aces           []BHAce        `json:"Aces"`
	IsDeleted      bool           `json:"IsDeleted"`
	IsACLProtected bool           `json:"IsACLProtected"`
	ContainedBy    *BHContainedBy `json:"ContainedBy"`
}

type BHRootCA struct {
	ObjectID       string         `json:"ObjectIdentifier"`
	Properties     map[string]any `json:"Properties"`
	DomainSID      *string        `json:"DomainSID"`
	Aces           []BHAce        `json:"Aces"`
	IsDeleted      bool           `json:"IsDeleted"`
	IsACLProtected bool           `json:"IsACLProtected"`
	ContainedBy    *BHContainedBy `json:"ContainedBy"`
}

type BHNTAuthStore struct {
	ObjectID       string         `json:"ObjectIdentifier"`
	Properties     map[string]any `json:"Properties"`
	DomainSID      *string        `json:"DomainSID"`
	Aces           []BHAce        `json:"Aces"`
	IsDeleted      bool           `json:"IsDeleted"`
	IsACLProtected bool           `json:"IsACLProtected"`
	ContainedBy    *BHContainedBy `json:"ContainedBy"`
}

type BHIssuancePolicy struct {
	ObjectID       string         `json:"ObjectIdentifier"`
	Properties     map[string]any `json:"Properties"`
	GroupLink      any            `json:"GroupLink"`
	Aces           []BHAce        `json:"Aces"`
	IsDeleted      bool           `json:"IsDeleted"`
	IsACLProtected bool           `json:"IsACLProtected"`
	ContainedBy    *BHContainedBy `json:"ContainedBy"`
}

type BHAce struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	AceType       string `json:"AceType,omitempty"`
	IsInherited   bool   `json:"IsInherited"`
}

type BHMetadata struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
}

// CollectSharpHound runs LDAP collectors and writes BloodHound-compatible JSON into a zip archive.
func (c *Conn) CollectBloodHound(
	collectors []string,
	outputPath string,
	baseDN string,
	dryRun bool,
) (string, error) {
	supported := map[string]func(string) (any, error){
		"users":            c.collectUsersBloodHound,
		"computers":        c.collectComputersBloodHound,
		"groups":           c.collectGroupsBloodHound,
		"domains":          c.collectDomainsBloodHound,
		"ous":              c.collectOUsBloodHound,
		"gpos":             c.collectGPOsBloodHound,
		"containers":       c.collectContainersBloodHound,
		"certtemplates":    c.collectCertTemplatesBloodHound,
		"enterprisecas":    c.collectEnterpriseCAsBloodHound,
		"aiacas":           c.collectAIACAsBloodHound,
		"rootcas":          c.collectRootCAsBloodHound,
		"ntauthstores":     c.collectNTAuthStoresBloodHound,
		"issuancepolicies": c.collectIssuancePoliciesBloodHound,
	}

	// normalize requested collectors
	var toRun []string
	if len(collectors) == 0 {
		for k := range supported {
			toRun = append(toRun, k)
		}
	} else {
		for _, req := range collectors {
			r := strings.ToLower(req)
			if _, ok := supported[r]; ok {
				toRun = append(toRun, r)
			}
		}
	}

	if len(toRun) == 0 {
		return "", fmt.Errorf("no valid collectors requested")
	}

	// Create temp dir
	tmpdir, err := os.MkdirTemp("", "ldaptickler-sharphound-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpdir)

	// If dryRun, skip file writes
	files := []string{}
	for _, name := range toRun {
		fn := supported[name]
		data, err := fn(baseDN)
		if err != nil {
			return "", fmt.Errorf(
				"collector %s failed: %w",
				name,
				err,
			)
		}

		if dryRun {
			continue
		}
		fname := filepath.Join(tmpdir, fmt.Sprintf("%s.json", name))
		f, err := os.Create(fname)
		if err != nil {
			return "", err
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
		files = append(files, fname)
	}

	if dryRun {
		return "dry-run", nil
	}

	if outputPath == "" {
		outputPath = fmt.Sprintf(
			"ldaptickler-%s.zip",
			time.Now().Format("20060102-150405"),
		)
	}

	// Create zip
	zf, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	defer zw.Close()

	for _, p := range files {
		if err := addFileToZip(zw, p); err != nil {
			return "", err
		}
	}

	return outputPath, nil
}

func addFileToZip(zw *zip.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w, err := zw.Create(filepath.Base(path))
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

// BloodHound-compatible collector implementations

func (c *Conn) collectUsersBloodHound(baseDN string) (any, error) {
	// Get regular users
	filter := "(objectCategory=person)"
	attrs := []string{
		// Identity attributes
		"distinguishedName", "sAMAccountName", "userPrincipalName", "objectSid", "objectGUID",
		// Display and contact info
		"displayName", "givenName", "sn", "mail", "mailNickname", "telephoneNumber", "mobile",
		// Group and delegation info
		"memberOf", "primaryGroupID", "sIDHistory",
		// Account settings
		"userAccountControl", "accountExpires", "scriptPath", "homeDirectory", "homeDrive",
		// Login and password info
		"lastLogon", "lastLogonTimestamp", "pwdLastSet", "passwordExpired",
		// Service principal names (for delegation)
		"servicePrincipalName",
		// Delegation and rights
		"adminCount", "userWorkstations", "msDS-AllowedToDelegateTo",
		// Metadata
		"description", "title", "department", "company", "manager",
		"whenCreated", "whenChanged",
		// Security info
		"nTSecurityDescriptor", "msDS-UserPasswordExpiryTimeComputed",
		// Shadow credentials
		"msDS-KeyCredentialLink",
	}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	// Also search for GMSA accounts in Managed Service Accounts container
	msaContainerDN := "CN=Managed Service Accounts," + baseDN
	msaRes, msaErr := c.getAllResults(
		1,
		"(objectClass=*)",
		attrs,
		msaContainerDN,
	)
	if msaErr == nil && len(msaRes) > 0 {
		res = append(res, msaRes...)
	}

	out := []BHUser{}
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)

	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		sid := firstOrEmpty(e, "objectSid")
		if sid == "" {
			continue // Skip if no SID
		}

		samAccountName := firstOrEmpty(e, "sAMAccountName")
		uacStr := firstOrEmpty(e, "userAccountControl")
		uacProps := parseUAC(uacStr)

		// Get primary group SID
		var primaryGroupSID *string
		if pgid := firstOrEmpty(e, "primaryGroupID"); pgid != "" {
			if domainSID != "" {
				pgSID := domainSID + "-" + pgid
				primaryGroupSID = &pgSID
			}
		}

		// Create name field: samaccountname@domain
		userName := samAccountName
		if samAccountName != "" && domain != "" {
			userName = samAccountName + "@" + strings.ToUpper(domain)
		}

		// Check if user has SPN (kerberoastable)
		spns := e["servicePrincipalName"]
		hasSPN := len(spns) > 0

		// Check for shadow credentials (msDS-KeyCredentialLink)
		hasShadowCreds := len(e["msDS-KeyCredentialLink"]) > 0

		// Parse SID History
		var sidHistory []string
		for _, sidHist := range e["sIDHistory"] {
			if sidHist != "" {
				sidHistory = append(sidHistory, sidHist)
			}
		}

		props := map[string]any{
			"name":              userName,
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"distinguishedname": dn,
			"samaccountname":    samAccountName,
			"description": toStringOrNil(
				firstOrEmpty(e, "description"),
			),
			"displayname": toStringOrNil(
				firstOrEmpty(e, "displayName"),
			),
			"title": toStringOrNil(
				firstOrEmpty(e, "title"),
			),
			"email": toStringOrNil(
				firstOrEmpty(e, "mail"),
			),
			"homedirectory": toStringOrNil(
				firstOrEmpty(e, "homeDirectory"),
			),
			"profilepath": toStringOrNil(
				firstOrEmpty(e, "profilePath"),
			),
			"logonscript": toStringOrNil(
				firstOrEmpty(e, "scriptPath"),
			),
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(e, "whenCreated"),
			),
			"unconstraineddelegation": uacProps["unconstraineddelegation"],
			"trustedtoauth":           uacProps["trustedtoauth"],
			"passwordnotreqd":         uacProps["passwordnotreqd"],
			"enabled":                 uacProps["enabled"],
			"dontreqpreauth":          uacProps["dontreqpreauth"],
			"pwdneverexpires":         uacProps["pwdneverexpires"],
			"sensitive":               uacProps["sensitive"],
			"smartcardrequired":       uacProps["smartcardrequired"],
			"encryptedtextpwdallowed": uacProps["encryptedtextpwdallowed"],
			"usedeskeyonly":           uacProps["usedeskeyonly"],
			"logonscriptenabled":      uacProps["logonscriptenabled"],
			"lockedout":               uacProps["lockedout"],
			"passwordcantchange":      uacProps["passwordcantchange"],
			"passwordexpired":         uacProps["passwordexpired"],
			"hasspn":                  hasSPN,
			"lastlogon": parseLDAPTimestamp(
				firstOrEmpty(e, "lastLogon"),
			),
			"lastlogontimestamp": parseLDAPGeneralizedTime(
				firstOrEmpty(e, "lastLogonTimestamp"),
			),
			"pwdlastset": parseLDAPTimestamp(
				firstOrEmpty(e, "pwdLastSet"),
			),
			"shadowcredentials": hasShadowCreds,
			"allowedtodelegate": nilIfEmpty(
				e["msDS-AllowedToDelegateTo"],
			),
			"serviceprincipalnames": nilIfEmpty(
				e["servicePrincipalName"],
			),
			"sidhistory": nilIfEmpty(sidHistory),
			"supportedencryptiontypes": toStringOrNil(
				firstOrEmpty(e, "msDS-SupportedEncryptionTypes"),
			),
			"useraccountcontrol": toInt(
				firstOrEmpty(e, "userAccountControl"),
			),
			"admincount": firstOrEmpty(
				e,
				"adminCount",
			) == "1",
			"sfupassword":     nil,
			"unicodepassword": nil,
			"unixpassword":    nil,
			"userpassword":    nil,
		}

		user := BHUser{
			ObjectID:                sid,
			PrimaryGroupSID:         primaryGroupSID,
			AllowedToDelegate:       e["msDS-AllowedToDelegateTo"],
			Properties:              props,
			Aces:                    []BHAce{},
			SPNTargets:              []string{},
			HasSIDHistory:           sidHistory,
			IsDeleted:               false,
			DomainSID:               domainSID,
			UnconstrainedDelegation: uacProps["unconstraineddelegation"].(bool),
			IsACLProtected:          false,
			ContainedBy:             nil,
		}
		out = append(out, user)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "users",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectComputersBloodHound(
	baseDN string,
) (any, error) {
	filter := "(&(objectCategory=computer))"
	attrs := []string{
		// Identity attributes
		"distinguishedName", "sAMAccountName", "objectSid", "objectGUID",
		// Network information
		"dNSHostName", "description",
		// OS and hardware
		"operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
		// Group membership
		"memberOf", "primaryGroupID",
		// Account settings
		"userAccountControl", "accountExpires",
		// Last activity
		"lastLogon", "lastLogonTimestamp", "pwdLastSet",
		// Service principals and delegation
		"servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		// LAPS detection
		"ms-mcs-admpwdexpirationtime",
		// Additional attributes
		"name", "cn", "whenCreated", "whenChanged",
		// Security
		"nTSecurityDescriptor", "msDS-Behavior-Version",
	}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	out := []BHComputer{}
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)

	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		sid := firstOrEmpty(e, "objectSid")
		if sid == "" {
			continue
		}

		samAccountName := firstOrEmpty(e, "sAMAccountName")

		// Get primary group SID
		var primaryGroupSID *string
		if pgid := firstOrEmpty(e, "primaryGroupID"); pgid != "" {
			if domainSID != "" {
				pgSID := domainSID + "-" + pgid
				primaryGroupSID = &pgSID
			}
		}

		// Parse UAC flags
		uacStr := firstOrEmpty(e, "userAccountControl")
		uacProps := parseUAC(uacStr)

		// Create name field: samaccountname@domain
		computerName := samAccountName
		if samAccountName != "" && domain != "" {
			computerName = samAccountName + "@" + strings.ToUpper(
				domain,
			)
		}

		// Check for LAPS
		hasLAPS := len(e["ms-mcs-admpwdexpirationtime"]) > 0

		// Check if computer is a DC
		isDC := false
		if pgid := firstOrEmpty(e, "primaryGroupID"); pgid == "516" {
			isDC = true
		}

		// Parse SID History
		var sidHistory []string
		for _, sidHist := range e["sIDHistory"] {
			if sidHist != "" {
				sidHistory = append(sidHistory, sidHist)
			}
		}

		props := map[string]any{
			"name":                    computerName,
			"domainsid":               domainSID,
			"domain":                  strings.ToUpper(domain),
			"distinguishedname":       dn,
			"unconstraineddelegation": uacProps["unconstraineddelegation"],
			"enabled":                 uacProps["enabled"],
			"trustedtoauth":           uacProps["trustedtoauth"],
			"encryptedtextpwdallowed": uacProps["encryptedtextpwdallowed"],
			"usedeskeyonly":           uacProps["usedeskeyonly"],
			"logonscriptenabled":      uacProps["logonscriptenabled"],
			"lockedout":               uacProps["lockedout"],
			"passwordexpired":         uacProps["passwordexpired"],
			"samaccountname":          samAccountName,
			"email": toStringOrNil(
				firstOrEmpty(e, "mail"),
			),
			"lastlogon": parseLDAPTimestamp(
				firstOrEmpty(e, "lastLogon"),
			),
			"lastlogontimestamp": parseLDAPGeneralizedTime(
				firstOrEmpty(e, "lastLogonTimestamp"),
			),
			"pwdlastset": parseLDAPTimestamp(
				firstOrEmpty(e, "pwdLastSet"),
			),
			"operatingsystem": toStringOrNil(
				firstOrEmpty(e, "operatingSystem"),
			),
			"dnshostname": toStringOrNil(
				firstOrEmpty(e, "dNSHostName"),
			),
			"description": toStringOrNil(
				firstOrEmpty(e, "description"),
			),
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(e, "whenCreated"),
			),
			"objectguid":   firstOrEmpty(e, "objectGUID"),
			"haslaps":      hasLAPS,
			"isdc":         isDC,
			"isreadonlydc": false,
			"admincount": firstOrEmpty(
				e,
				"adminCount",
			) == "1",
			"serviceprincipalnames": nilIfEmpty(
				e["servicePrincipalName"],
			),
			"sidhistory": nilIfEmpty(sidHistory),
			"supportedencryptiontypes": nilIfEmpty(
				e["msDS-SupportedEncryptionTypes"],
			),
			"allowedtodelegate": nilIfEmpty(
				e["msDS-AllowedToDelegateTo"],
			),
			"useraccountcontrol": toInt(
				firstOrEmpty(e, "userAccountControl"),
			),
		}

		computer := BHComputer{
			ObjectID:        sid,
			AllowedToAct:    []string{},
			PrimaryGroupSID: primaryGroupSID,
			LocalAdmins: BHCollectionResult{
				Collected:     false,
				FailureReason: nil,
				Results:       []string{},
			},
			PSRemoteUsers: BHCollectionResult{
				Collected:     false,
				FailureReason: nil,
				Results:       []string{},
			},
			Properties: props,
			RemoteDesktopUsers: BHCollectionResult{
				Collected:     false,
				FailureReason: nil,
				Results:       []string{},
			},
			DcomUsers: BHCollectionResult{
				Collected:     false,
				FailureReason: nil,
				Results:       []string{},
			},
			AllowedToDelegate: sliceOrNil(
				e["msDS-AllowedToDelegateTo"],
			),
			Sessions: BHCollectionResult{
				Collected:     false,
				FailureReason: nil,
				Results:       []string{},
			},
			PrivilegedSessions: BHCollectionResult{
				Collected:     false,
				FailureReason: nil,
				Results:       []string{},
			},
			RegistrySessions: BHCollectionResult{
				Collected:     false,
				FailureReason: nil,
				Results:       []string{},
			},
			Aces:                    []BHAce{},
			HasSIDHistory:           sliceOrNil(sidHistory),
			IsDeleted:               false,
			Status:                  nil,
			IsDC:                    isDC,
			UnconstrainedDelegation: uacProps["unconstraineddelegation"].(bool),
			DomainSID:               domainSID,
			IsACLProtected:          false,
			ContainedBy:             nil,
		}
		out = append(out, computer)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "computers",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectGroupsBloodHound(baseDN string) (any, error) {
	filter := "(objectCategory=group)"
	attrs := []string{
		// Identity attributes
		"distinguishedName", "cn", "sAMAccountName", "objectSid", "objectGUID",
		// Membership
		"member", "memberOf",
		// Group type and scope
		"groupType",
		// Admin and account info
		"adminCount",
		// Metadata
		"description", "mail", "mailNickname",
		"whenCreated", "whenChanged",
		// Security
		"nTSecurityDescriptor",
	}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	// Also search for built-in groups in the BUILTIN container
	builtinContainerDN := "CN=BUILTIN," + baseDN
	builtinRes, builtinErr := c.getAllResults(
		1,
		filter,
		attrs,
		builtinContainerDN,
	)
	if builtinErr == nil && len(builtinRes) > 0 {
		res = append(res, builtinRes...)
	}

	out := []BHGroup{}
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)

	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		sid := firstOrEmpty(e, "objectSid")
		if sid == "" {
			continue
		}

		members := []BHMember{}
		for _, memberDN := range e["member"] {
			// For each member, we need to resolve its SID and type
			memberSID := c.resolveSIDFromDN(memberDN)
			if memberSID == "" {
				memberSID = memberDN // Fall back to DN if SID not found
			}

			// Determine object type from DN
			objType := "User" // Default
			if strings.Contains(
				strings.ToLower(memberDN),
				"cn=computers",
			) {
				objType = "Computer"
			} else if strings.Contains(strings.ToLower(memberDN), "objectClass=group") || c.isGroup(memberDN) {
				objType = "Group"
			}

			members = append(members, BHMember{
				ObjectIdentifier: memberSID,
				ObjectType:       objType,
			})
		}

		// Parse group type to determine scope
		groupType := firstOrEmpty(e, "groupType")
		var groupScope string
		if groupType != "" {
			// Extract scope from group type bitmask
			if strings.Contains(groupType, "-2147483646") ||
				strings.Contains(groupType, "2147483650") {
				groupScope = "Universal"
			} else if strings.Contains(groupType, "4") || strings.Contains(groupType, "-2147483644") {
				groupScope = "Domain Local"
			} else if strings.Contains(groupType, "2") || strings.Contains(groupType, "-2147483646") {
				groupScope = "Global"
			} else {
				groupScope = "Unknown"
			}
		}

		// Parse SID History
		var sidHistory []string
		for _, sidHist := range e["sIDHistory"] {
			if sidHist != "" {
				sidHistory = append(sidHistory, sidHist)
			}
		}

		props := map[string]any{
			"domain":    strings.ToUpper(domain),
			"domainsid": domainSID,
			"highvalue": false,
			"name": firstOrEmpty(
				e,
				"sAMAccountName",
			) + "@" + strings.ToUpper(
				domain,
			),
			"distinguishedname": dn,
			"samaccountname":    firstOrEmpty(e, "sAMAccountName"),
			"mail":              firstOrEmpty(e, "mail"),
			"description":       firstOrEmpty(e, "description"),
			"admincount":        firstOrEmpty(e, "adminCount") == "1",
			"displayname":       firstOrEmpty(e, "cn"),
			"groupscope":        groupScope,
			"sidhistory":        sidHistory,
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(e, "whenCreated"),
			),
		}

		group := BHGroup{
			ObjectID:   sid,
			Properties: props,
			Members:    members,
			Aces:       []BHAce{},
			IsDeleted:  false,
		}
		out = append(out, group)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "groups",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectDomainsBloodHound(baseDN string) (any, error) {
	// Match the domain object at the baseDN
	// First try with scope 0 (base), then fall back to scope 2 (subtree) if needed
	filter := "(objectClass=domain)"
	attrs := []string{
		// Identity and basic info
		"distinguishedName", "objectSid", "objectGUID", "name", "description",
		// Domain configuration
		"nETBIOSName", "dc",
		// Functional level and features
		"msDS-Behavior-Version",
		// Password policy attributes
		"maxPwdAge", "minPwdAge", "minPwdLength", "pwdHistoryLength",
		// Lockout policy
		"lockoutDuration", "lockoutObservationWindow", "lockoutThreshold",
		// Domain info
		"dSHeuristics", "pwdProperties",
		// Machine account quota
		"ms-DS-MachineAccountQuota",
		// Smart card settings
		"ms-DS-ExpirePasswordsOnSmartCardOnlyAccounts",
		// Metadata
		"whenCreated", "whenChanged",
		// Security and replication
		"nTSecurityDescriptor", "objectVersion",
	}
	res, err := c.getAllResults(
		0,
		filter,
		attrs,
		baseDN,
	) // Base scope - query exactly at baseDN
	if err != nil || len(res) == 0 {
		// Fallback to subtree scope if base scope didn't work
		res, err = c.getAllResults(2, filter, attrs, baseDN)
		if err != nil {
			return nil, err
		}
	}

	out := []BHDomain{}

	// If we got results, process them
	if len(res) > 0 {
		for _, e := range res {
			sid := firstOrEmpty(e, "objectSid")
			// Don't skip if no SID - still create domain object for visibility

			dn := firstOrEmpty(e, "DN")
			if dn == "" {
				dn = baseDN // Fallback to baseDN if not found
			}
			domain := strings.ToUpper(extractDomainFromDN(dn))
			if domain == "" {
				domain = strings.ToUpper(extractDomainFromDN(baseDN))
			}
			description := firstOrEmpty(e, "description")
			whenCreated := parseLDAPGeneralizedTime(
				firstOrEmpty(e, "whenCreated"),
			)

			props := map[string]any{
				"name": strings.ToUpper(
					domain,
				),
				"domain": strings.ToUpper(
					domain,
				),
				"domainsid":         sid,
				"distinguishedname": dn,
				"description": toStringOrNil(
					description,
				),
				"functionallevel": "Unknown",
				"highvalue":       true,
				"whencreated":     whenCreated,
				"collected":       true,
				"netbios": toStringOrNil(
					firstOrEmpty(e, "nETBIOSName"),
				),
				"dsheuristics": toStringOrNil(
					firstOrEmpty(e, "dSHeuristics"),
				),
				"pwdproperties": toInt(
					firstOrEmpty(e, "pwdProperties"),
				),
				"maxpwdage": toStringOrNil(
					firstOrEmpty(e, "maxPwdAge"),
				),
				"minpwdage": toStringOrNil(
					firstOrEmpty(e, "minPwdAge"),
				),
				"minpwdlength": toInt(
					firstOrEmpty(e, "minPwdLength"),
				),
				"pwdhistorylength": toInt(
					firstOrEmpty(e, "pwdHistoryLength"),
				),
				"lockoutduration": toStringOrNil(
					firstOrEmpty(e, "lockoutDuration"),
				),
				"lockoutobservationwindow": toInt(
					firstOrEmpty(e, "lockoutObservationWindow"),
				),
				"lockoutthreshold": toInt(
					firstOrEmpty(e, "lockoutThreshold"),
				),
				"machineaccountquota": toInt(
					firstOrEmpty(e, "ms-DS-MachineAccountQuota"),
				),
				"expirepasswordsonsmartcardonlyaccounts": firstOrEmpty(
					e,
					"ms-DS-ExpirePasswordsOnSmartCardOnlyAccounts",
				) == "1",
			}

			// Collect trusts for this domain
			trusts := c.collectDomainsForObject(dn)

			domainObj := BHDomain{
				ObjectID:     sid,
				Properties:   props,
				Trusts:       trusts,
				Aces:         []BHAce{},
				Links:        []string{},
				ChildObjects: []string{},
				GPOChanges: BHGPOChanges{
					AffectedComputers:  []string{},
					DcomUsers:          []string{},
					LocalAdmins:        []string{},
					PSRemoteUsers:      []string{},
					RemoteDesktopUsers: []string{},
				},
				IsDeleted:            false,
				ContainedBy:          nil,
				ForestRootIdentifier: nil,
				InheritanceHashes:    []any{},
				IsACLProtected:       false,
			}
			out = append(out, domainObj)
		}
	} else {
		// If query returned nothing, create domain object from baseDN
		domain := strings.ToUpper(extractDomainFromDN(baseDN))

		// Try to get domain SID
		domainSID := c.getDomainSID(baseDN)
		if domainSID == "" {
			// Generate a placeholder SID if we can't get the real one
			domainSID = "S-1-5-21-0-0-0"
		}

		props := map[string]any{
			"name":                                   strings.ToUpper(domain),
			"domain":                                 strings.ToUpper(domain),
			"domainsid":                              domainSID,
			"distinguishedname":                      baseDN,
			"description":                            "",
			"functionallevel":                        "Unknown",
			"highvalue":                              true,
			"whencreated":                            int64(0),
			"collected":                              true,
			"netbios":                                "",
			"dsheuristics":                           "",
			"pwdproperties":                          "",
			"maxpwdage":                              "",
			"minpwdage":                              "",
			"minpwdlength":                           "",
			"pwdhistorylength":                       "",
			"lockoutduration":                        "",
			"lockoutobservationwindow":               "",
			"lockoutthreshold":                       "",
			"machineaccountquota":                    "",
			"expirepasswordsonsmartcardonlyaccounts": "",
		}

		domainObj := BHDomain{
			ObjectID:     domainSID,
			Properties:   props,
			Trusts:       []string{},
			Aces:         []BHAce{},
			Links:        []string{},
			ChildObjects: []string{},
			GPOChanges: BHGPOChanges{
				AffectedComputers:  []string{},
				DcomUsers:          []string{},
				LocalAdmins:        []string{},
				PSRemoteUsers:      []string{},
				RemoteDesktopUsers: []string{},
			},
			IsDeleted:            false,
			ContainedBy:          nil,
			ForestRootIdentifier: nil,
			InheritanceHashes:    []any{},
			IsACLProtected:       false,
		}
		out = append(out, domainObj)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "domains",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectOUsBloodHound(baseDN string) (any, error) {
	filter := "(objectClass=organizationalUnit)"
	attrs := []string{
		// Identity and basic info
		"distinguishedName", "objectGUID", "name", "description",
		// Group Policy
		"gPLink", "gPOptions",
		// Metadata
		"whenCreated", "whenChanged",
		// Security
		"nTSecurityDescriptor",
	}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	out := []map[string]any{}
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)

	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		guid := firstOrEmpty(e, "objectGUID")
		if guid == "" {
			guid = dn
		}

		// Check if GP inheritance is blocked (gPOptions bit)
		blockInheritance := false
		gpOptions := firstOrEmpty(e, "gPOptions")
		if gpOptions == "1" {
			blockInheritance = true
		}

		props := map[string]any{
			"name":              firstOrEmpty(e, "name"),
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"distinguishedname": dn,
			"description":       firstOrEmpty(e, "description"),
			"blocksinheritance": blockInheritance,
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(e, "whenCreated"),
			),
		}

		gpLink := firstOrEmpty(e, "gPLink")
		linkedGPOs := []string{}
		if gpLink != "" {
			parts := strings.Split(gpLink, "[LDAP://")
			for i := 1; i < len(parts); i++ {
				if idx := strings.Index(parts[i], ";"); idx > 0 {
					linkedGPOs = append(
						linkedGPOs,
						"LDAP://"+parts[i][:idx],
					)
				}
			}
		}

		ou := map[string]any{
			"ObjectIdentifier": guid,
			"Properties":       props,
		}
		if len(linkedGPOs) > 0 {
			ou["LinkedGPOs"] = linkedGPOs
		}
		out = append(out, ou)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "ous",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectGPOsBloodHound(baseDN string) (any, error) {
	filter := "(objectClass=groupPolicyContainer)"
	attrs := []string{
		// Identity and naming
		"distinguishedName", "displayName", "name", "cn", "objectGUID",
		// GPO configuration
		"gPCFunctionalityVersion", "gPCFileSysPath",
		// Status and versioning
		"versionNumber",
		// Metadata
		"description", "whenCreated", "whenChanged",
	}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	out := []map[string]any{}
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)

	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		name := firstOrEmpty(e, "displayName")
		if name == "" {
			name = firstOrEmpty(e, "cn")
		}

		// Parse GPO status from versionNumber
		gpcPath := firstOrEmpty(e, "gPCFileSysPath")
		gpoStatus := "Unknown"
		if gpcPath != "" {
			gpoStatus = "Enabled"
		}

		props := map[string]any{
			"name":              name,
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"distinguishedname": dn,
			"gpcpath":           gpcPath,
			"gpostatus":         gpoStatus,
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(e, "whenCreated"),
			),
		}

		gpo := map[string]any{
			"ObjectIdentifier": dn,
			"Properties":       props,
		}
		out = append(out, gpo)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "gpos",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectContainersBloodHound(
	baseDN string,
) (any, error) {
	// Collect all container objects from both domain and configuration partitions
	filter := "(|(objectClass=container)(objectClass=organizationalUnit))"
	attrs := []string{
		// Identity and basic info
		"distinguishedName", "objectGUID", "name", "description",
		// Metadata
		"whenCreated", "whenChanged",
		// Security
		"nTSecurityDescriptor",
	}

	// Search domain partition only - SharpHound uses subtree scope on domain
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		// If domain search fails, return error
		return nil, err
	}

	// Also search Configuration partition for containers
	// SharpHound searches the entire Configuration partition with subtree scope
	configDN := "CN=Configuration," + baseDN
	configRes, err := c.getAllResults(2, filter, attrs, configDN)
	if err != nil {
		fmt.Printf(
			"[!] Configuration partition search error: %v\n",
			err,
		)
	} else if len(configRes) > 0 {
		res = append(res, configRes...)
	} else {
		fmt.Printf("[!] Configuration partition search returned 0 results\n")
	}

	out := []map[string]any{}
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)

	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		guid := firstOrEmpty(e, "objectGUID")
		if guid == "" {
			guid = dn
		}

		props := map[string]any{
			"name":              firstOrEmpty(e, "name"),
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"distinguishedname": dn,
			"description":       firstOrEmpty(e, "description"),
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(e, "whenCreated"),
			),
		}

		container := map[string]any{
			"ObjectIdentifier": guid,
			"Properties":       props,
		}
		out = append(out, container)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "containers",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

// Helper functions

func firstOrEmpty(m map[string][]string, k string) string {
	if v, ok := m[k]; ok && len(v) > 0 {
		return v[0]
	}
	if v, ok := m[strings.ToLower(k)]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// Helper functions for type conversion
func toInt(s string) any {
	if s == "" {
		return nil
	}
	var val int64
	if _, err := fmt.Sscanf(s, "%d", &val); err != nil {
		return nil
	}
	return int(val)
}

func toStringOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nilIfEmpty(slice []string) any {
	if len(slice) == 0 {
		return nil
	}
	return slice
}

func sliceOrNil(slice []string) []string {
	if len(slice) == 0 {
		return nil
	}
	return slice
}

// parseUAC decodes userAccountControl flags
func parseUAC(uacStr string) map[string]any {
	result := map[string]any{
		"unconstraineddelegation": false,
		"trustedtoauth":           false,
		"passwordnotreqd":         false,
		"enabled":                 true,
		"dontreqpreauth":          false,
		"pwdneverexpires":         false,
		"sensitive":               false,
		"smartcardrequired":       false,
		"encryptedtextpwdallowed": false,
		"usedeskeyonly":           false,
		"logonscriptenabled":      false,
		"lockedout":               false,
		"passwordcantchange":      false,
		"passwordexpired":         false,
	}

	if uacStr == "" {
		return result
	}

	// Parse the UAC value (already a numeric string from LDAP)
	var uac uint32
	_, err := fmt.Sscanf(uacStr, "%d", &uac)
	if err != nil {
		return result
	}

	// Bit flags from ldaptickler.go
	const (
		UACDontExpirePassword         = 0x10000
		UACNotDelegated               = 0x100000
		UACTrustedForDelegation       = 0x80000
		UACTrustedToAuthForDelegation = 0x1000000
		UACAccountDisable             = 0x2
		UACPasswordRequired           = 0x800000
		UACDontReqPreAuth             = 0x400000
		UACSmartCardRequired          = 0x40000
		UACEncryptedTextPwdAllowed    = 0x80
		UACUseDesKeyOnly              = 0x200000
		UACLogonScript                = 0x1
		UACLockedOut                  = 0x10
		UACPasswordCantChange         = 0x40
		UACPasswordExpired            = 0x800
	)

	result["unconstraineddelegation"] = (uac & UACTrustedForDelegation) != 0
	result["trustedtoauth"] = (uac & UACTrustedToAuthForDelegation) != 0
	result["passwordnotreqd"] = (uac & UACPasswordRequired) == 0
	result["enabled"] = (uac & UACAccountDisable) == 0
	result["dontreqpreauth"] = (uac & UACDontReqPreAuth) != 0
	result["pwdneverexpires"] = (uac & UACDontExpirePassword) != 0
	result["sensitive"] = (uac & UACNotDelegated) != 0
	result["smartcardrequired"] = (uac & UACSmartCardRequired) != 0
	result["encryptedtextpwdallowed"] = (uac & UACEncryptedTextPwdAllowed) != 0
	result["usedeskeyonly"] = (uac & UACUseDesKeyOnly) != 0
	result["logonscriptenabled"] = (uac & UACLogonScript) != 0
	result["lockedout"] = (uac & UACLockedOut) != 0
	result["passwordcantchange"] = (uac & UACPasswordCantChange) != 0
	result["passwordexpired"] = (uac & UACPasswordExpired) != 0

	return result
}

// parseLDAPTimestamp converts Windows FILETIME (used by lastLogon, pwdLastSet) to Unix timestamp
// FILETIME is stored as a 64-bit integer representing 100-nanosecond intervals since 1601-01-01
func parseLDAPTimestamp(timeStr string) int64 {
	if timeStr == "" {
		return 0
	}
	// Parse as 64-bit integer
	var ft int64
	_, err := fmt.Sscanf(timeStr, "%d", &ft)
	if err != nil {
		return 0
	}
	// 116444736000000000 is the number of 100-nanosecond intervals from 1601-01-01 to 1970-01-01
	unixTime := (ft - 116444736000000000) / 10000000
	return unixTime
}

// parseLDAPGeneralizedTime converts LDAP Generalized Time (YYYYMMDDhhmmssZ) to Unix timestamp
func parseLDAPGeneralizedTime(timeStr string) int64 {
	if timeStr == "" {
		return 0
	}
	// Remove the trailing Z if present
	if len(timeStr) > 0 && timeStr[len(timeStr)-1] == 'Z' {
		timeStr = timeStr[:len(timeStr)-1]
	}
	// Parse format: YYYYMMDDhhmmss
	if len(timeStr) < 14 {
		return 0
	}
	var year, month, day, hour, min, sec int
	_, err := fmt.Sscanf(
		timeStr[:14],
		"%4d%2d%2d%2d%2d%2d",
		&year,
		&month,
		&day,
		&hour,
		&min,
		&sec,
	)
	if err != nil {
		return 0
	}

	// Create a time value
	t := time.Date(
		year,
		time.Month(month),
		day,
		hour,
		min,
		sec,
		0,
		time.UTC,
	)
	return t.Unix()
}

// getDomainSID retrieves the domain SID from the domain object
func (c *Conn) getDomainSID(baseDN string) string {
	filter := "(objectClass=domain)"
	attrs := []string{"objectSid"}
	res, err := c.getAllResults(
		0,
		filter,
		attrs,
		baseDN,
	) // Base scope for domain object
	if err != nil || len(res) == 0 {
		return ""
	}
	return firstOrEmpty(res[0], "objectSid")
}

// resolveSIDFromDN looks up the objectSid for a given DN
func (c *Conn) resolveSIDFromDN(dn string) string {
	if dn == "" {
		return ""
	}
	// Search for the object by its DN
	filter := "(distinguishedName=" + dn + ")"
	attrs := []string{"objectSid"}
	res, err := c.getAllResults(
		0,
		filter,
		attrs,
		dn,
	) // Base scope search at the DN
	if err != nil || len(res) == 0 {
		return ""
	}
	return firstOrEmpty(res[0], "objectSid")
}

// isGroup checks if a DN refers to a group object
func (c *Conn) isGroup(dn string) bool {
	if dn == "" {
		return false
	}
	filter := "(&(distinguishedName=" + dn + ")(objectCategory=group))"
	attrs := []string{"cn"}
	res, err := c.getAllResults(0, filter, attrs, dn)
	if err != nil || len(res) == 0 {
		return false
	}
	return true
}

// collectDomainsForObject collects domain trusts for a given domain DN
func (c *Conn) collectDomainsForObject(baseDN string) []string {
	filter := "(objectClass=trustedDomain)"
	attrs := []string{"cn", "objectSid"}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil || len(res) == 0 {
		return []string{}
	}

	var trusts []string
	for _, trust := range res {
		sid := firstOrEmpty(trust, "objectSid")
		if sid != "" {
			trusts = append(trusts, sid)
		}
	}
	return trusts
}

func extractDomainFromDN(dn string) string {
	// Convert DN like "CN=user,CN=Users,DC=domain,DC=com" to "domain.com"
	parts := strings.Split(dn, ",")
	var dcParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "DC=") {
			dcParts = append(dcParts, part[3:])
		}
	}
	if len(dcParts) > 0 {
		return strings.ToLower(strings.Join(dcParts, "."))
	}
	return ""
}

// buildPKIConfigDN constructs the PKI Configuration container DN from the domain baseDN
func buildPKIConfigDN(baseDN string) string {
	return "CN=Public Key Services,CN=Services,CN=Configuration," + baseDN
}

// Helper function to find certificate template containers and Root CAs
func (c *Conn) getCertTemplateContainerGUID(baseDN string) *string {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	containerDN := "CN=Certificate Templates," + pkiBaseDN
	filter := "(objectClass=container)"
	attrs := []string{"objectGUID"}

	res, err := c.getAllResults(0, filter, attrs, containerDN)
	if err != nil || len(res) == 0 {
		return nil
	}

	if guid := firstOrEmpty(res[0], "objectGUID"); guid != "" {
		return &guid
	}
	return nil
}

func (c *Conn) findRootCAForEnterprise(baseDN string) *string {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	filter := "(objectClass=certificationAuthority)"
	attrs := []string{"objectGUID"}

	res, err := c.getAllResults(2, filter, attrs, pkiBaseDN)
	if err != nil || len(res) == 0 {
		return nil
	}

	if guid := firstOrEmpty(res[0], "objectGUID"); guid != "" {
		return &guid
	}
	return nil
}

func (c *Conn) getCertificationAuthoritiesContainerGUID(
	baseDN string,
) *string {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	containerDN := "CN=Certification Authorities," + pkiBaseDN
	filter := "(objectClass=container)"
	attrs := []string{"objectGUID"}

	res, err := c.getAllResults(0, filter, attrs, containerDN)
	if err != nil || len(res) == 0 {
		return nil
	}

	if guid := firstOrEmpty(res[0], "objectGUID"); guid != "" {
		return &guid
	}
	return nil
}

func (c *Conn) getPKIContainerGUID(baseDN string) *string {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	filter := "(objectClass=container)"
	attrs := []string{"objectGUID"}

	res, err := c.getAllResults(0, filter, attrs, pkiBaseDN)
	if err != nil || len(res) == 0 {
		return nil
	}

	if guid := firstOrEmpty(res[0], "objectGUID"); guid != "" {
		return &guid
	}
	return nil
}

// findCertTemplateGUIDsByCA finds which certificate templates can be issued by an Enterprise CA
// In AD, all templates published in the forest are available to all CAs, but specific
// templates can be restricted. For now, we return all templates in the domain as all CAs
// can theoretically issue them unless restricted via permissions.
func (c *Conn) findCertTemplateGUIDsByCA(baseDN string) []string {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	filter := "(objectClass=pKICertificateTemplate)"
	attrs := []string{"objectGUID"}

	res, err := c.getAllResults(2, filter, attrs, pkiBaseDN)
	if err != nil {
		return []string{}
	}

	var guids []string
	for _, entry := range res {
		if guid := firstOrEmpty(entry, "objectGUID"); guid != "" {
			guids = append(guids, guid)
		}
	}
	return guids
}

// getContainerGUIDByDN retrieves the objectGUID of a container by its DN
func (c *Conn) getContainerGUIDByDN(dn string) string {
	attrs := []string{"objectGUID"}
	result, err := c.ldapSearch(dn, 0, "(objectClass=*)", attrs)
	if err != nil || len(result.Entries) == 0 {
		return ""
	}

	for _, attr := range result.Entries[0].Attributes {
		if attr.Name == "objectGUID" && len(attr.ByteValues) > 0 {
			return decodeGUID(attr.ByteValues[0])
		}
	}
	return ""
}

// findComputerByDNSName finds a computer GUID by matching its dNSHostName
func (c *Conn) findComputerByDNSName(
	dnsHostname string,
	baseDN string,
) *string {
	if dnsHostname == "" {
		return nil
	}

	filter := "(&(objectClass=computer)(dNSHostName=" + escapeFilterValue(
		dnsHostname,
	) + "))"
	attrs := []string{"objectGUID"}

	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil || len(res) == 0 {
		return nil
	}

	if guid := firstOrEmpty(res[0], "objectGUID"); guid != "" {
		return &guid
	}
	return nil
}

// escapeFilterValue escapes special characters in LDAP filter values
func escapeFilterValue(value string) string {
	replacer := strings.NewReplacer(
		"*", "\\2a",
		"(", "\\28",
		")", "\\29",
		"\\", "\\5c",
		"/", "\\2f",
		"\x00", "\\00",
	)
	return replacer.Replace(value)
}

// ADCS Collectors - Active Directory Certificate Services collection

func (c *Conn) collectCertTemplatesBloodHound(
	baseDN string,
) (any, error) {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	filter := "(objectClass=pKICertificateTemplate)"
	attrs := []string{
		"objectGUID", "displayName", "distinguishedName", "cn", "whenCreated",
		"msPKI-RA-Application-Policies", "msPKI-Certificate-Application-Policy",
		"msPKI-Enrollment-Flag", "pKIExpirationPeriod", "msPKI-Certificate-Policy",
	}
	res, err := c.getAllResults(2, filter, attrs, pkiBaseDN)
	if err != nil {
		// Return empty result instead of error if no entries found
		return map[string]any{
			"data": []BHCertTemplate{},
			"meta": map[string]any{
				"methods": 0,
				"type":    "certtemplates",
				"count":   0,
				"version": 5,
			},
		}, nil
	}

	var out []BHCertTemplate
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)
	templateContainerGUID := c.getCertTemplateContainerGUID(baseDN)

	for _, entry := range res {
		dn := firstOrEmpty(entry, "DN")
		name := firstOrEmpty(entry, "cn")
		guid := firstOrEmpty(entry, "objectGUID")

		if name == "" {
			name = dn
		}

		props := map[string]any{
			"distinguishedname": dn,
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"name": name + "@" + strings.ToUpper(
				domain,
			),
			"displayname": toStringOrNil(
				firstOrEmpty(entry, "displayName"),
			),
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(entry, "whenCreated"),
			),
			"oid":            "",
			"validityperiod": "",
			"renewalperiod":  "",
			"ekus": nilIfEmpty(
				entry["msPKI-RA-Application-Policies"],
			),
			"effectiveekus": nilIfEmpty(
				entry["msPKI-Certificate-Application-Policy"],
			),
			"authenticationenabled":         true,
			"schannelauthenticationenabled": false,
			"certificatepolicy": toStringOrNil(
				firstOrEmpty(entry, "msPKI-Certificate-Policy"),
			),
			"certificateapplicationpolicy": nilIfEmpty(
				entry["msPKI-RA-Application-Policies"],
			),
			"applicationpolicies": nilIfEmpty(
				entry["msPKI-RA-Application-Policies"],
			),
			"issuancepolicies": nilIfEmpty(
				entry["msPKI-Certificate-Policy"],
			),
		}

		// Set ContainedBy if we found the container
		var containedBy *BHContainedBy
		if templateContainerGUID != nil {
			containedBy = &BHContainedBy{
				ObjectIdentifier: *templateContainerGUID,
				ObjectType:       "Container",
			}
		}

		certObj := BHCertTemplate{
			ObjectID:       guid,
			Properties:     props,
			Aces:           []BHAce{},
			IsDeleted:      false,
			IsACLProtected: false,
			ContainedBy:    containedBy,
		}
		out = append(out, certObj)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "certtemplates",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectEnterpriseCAsBloodHound(
	baseDN string,
) (any, error) {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	filter := "(objectClass=pKIEnrollmentService)"
	attrs := []string{
		"objectGUID", "cn", "distinguishedName", "dNSHostName", "whenCreated",
	}
	res, err := c.getAllResults(2, filter, attrs, pkiBaseDN)
	if err != nil {
		// Return empty result instead of error if no entries found
		return map[string]any{
			"data": []BHEnterpriseCA{},
			"meta": map[string]any{
				"methods": 0,
				"type":    "enterprisecas",
				"count":   0,
				"version": 5,
			},
		}, nil
	}

	var out []BHEnterpriseCA
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)
	issuedByCA := c.findRootCAForEnterprise(baseDN)

	for _, entry := range res {
		dn := firstOrEmpty(entry, "DN")
		name := firstOrEmpty(entry, "cn")
		guid := firstOrEmpty(entry, "objectGUID")
		dnsHostnameStr := firstOrEmpty(entry, "dNSHostName")
		var dnsHostname *string
		if dnsHostnameStr != "" {
			dnsHostname = &dnsHostnameStr
		}

		if name == "" {
			name = dn
		}

		// Find hosting computer by DNS hostname
		var hostingComputer *string
		if dnsHostnameStr != "" {
			hostingComputer = c.findComputerByDNSName(
				dnsHostnameStr,
				baseDN,
			)
		}

		// Find certificate templates published by this CA
		templateGUIDs := c.findCertTemplateGUIDsByCA(baseDN)
		enabledTemplates := []BHMember{}
		for _, guid := range templateGUIDs {
			enabledTemplates = append(enabledTemplates, BHMember{
				ObjectIdentifier: guid,
				ObjectType:       "CertTemplate",
			})
		}

		// Find parent container (Enrollment Services) for ContainedBy relationship
		var containedBy *BHContainedBy
		parts := strings.Split(dn, ",")
		if len(parts) > 1 {
			parentDN := strings.Join(parts[1:], ",")
			parentGUID := c.getContainerGUIDByDN(parentDN)
			if parentGUID != "" {
				containedBy = &BHContainedBy{
					ObjectIdentifier: parentGUID,
					ObjectType:       "Container",
				}
			}
		}

		props := map[string]any{
			"distinguishedname": dn,
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"name":              name + "@" + strings.ToUpper(domain),
			"dnshostname":       dnsHostname,
			"caname":            name,
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(entry, "whenCreated"),
			),
			"flags": 0,
		}

		caObj := BHEnterpriseCA{
			ObjectID:                guid,
			Properties:              props,
			HostingComputer:         hostingComputer,
			CARegistryData:          nil,
			EnabledCertTemplates:    enabledTemplates,
			HttpEnrollmentEndpoints: []string{},
			IssuedBy:                issuedByCA,
			Aces:                    []BHAce{},
			IsDeleted:               false,
			IsACLProtected:          false,
			ContainedBy:             containedBy,
		}
		out = append(out, caObj)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "enterprisecas",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectAIACAsBloodHound(baseDN string) (any, error) {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	aiaContainerDN := "CN=AIA," + pkiBaseDN
	attrs := []string{
		"objectGUID", "cn", "distinguishedName", "whenCreated",
		"crossCertificatePair",
	}
	// Search in AIA container for all objects (looking for CA objects)
	res, err := c.getAllResults(
		1,
		"(objectClass=*)",
		attrs,
		aiaContainerDN,
	)
	if err != nil || len(res) == 0 {
		// If that doesn't work, try searching whole PKI base for anything in AIA
		res, _ = c.getAllResults(
			2,
			"(|(objectClass=pkiAIA)(cn=*))",
			attrs,
			aiaContainerDN,
		)
	}
	// Filter out the AIA container itself if it was returned
	filtered := make([]map[string][]string, 0)
	for _, entry := range res {
		dn := firstOrEmpty(entry, "DN")
		cn := firstOrEmpty(entry, "cn")
		// Skip the AIA container itself (where cn=AIA and dn matches the container)
		if !(cn == "AIA" && dn == aiaContainerDN) {
			filtered = append(filtered, entry)
		}
	}
	res = filtered

	var out []BHAIACA
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)

	for _, entry := range res {
		dn := firstOrEmpty(entry, "DN")
		name := firstOrEmpty(entry, "cn")
		guid := firstOrEmpty(entry, "objectGUID")
		hasCrossCert := len(entry["crossCertificatePair"]) > 0

		if name == "" {
			name = dn
		}

		props := map[string]any{
			"distinguishedname": dn,
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"name": name + "@" + strings.ToUpper(
				domain,
			),
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(entry, "whenCreated"),
			),
			"hascrosscertificatepair": hasCrossCert,
			"crosscertificatepair": nilIfEmpty(
				entry["crossCertificatePair"],
			),
		}

		aiaObj := BHAIACA{
			ObjectID:       guid,
			Properties:     props,
			Aces:           []BHAce{},
			IsDeleted:      false,
			IsACLProtected: false,
			ContainedBy:    nil,
		}
		out = append(out, aiaObj)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "aiacas",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectRootCAsBloodHound(baseDN string) (any, error) {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	// Search only in the Certification Authorities container to exclude NTAuthCertificates
	rootCAsContainerDN := "CN=Certification Authorities," + pkiBaseDN
	filter := "(objectClass=certificationAuthority)"
	attrs := []string{
		"objectGUID", "cn", "distinguishedName", "whenCreated",
	}
	res, err := c.getAllResults(1, filter, attrs, rootCAsContainerDN)
	if err != nil {
		// Return empty result instead of error if no entries found
		return map[string]any{
			"data": []BHRootCA{},
			"meta": map[string]any{
				"methods": 0,
				"type":    "rootcas",
				"count":   0,
				"version": 5,
			},
		}, nil
	}

	var out []BHRootCA
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)
	rootCAContainerGUID := c.getCertificationAuthoritiesContainerGUID(
		baseDN,
	)

	for _, entry := range res {
		dn := firstOrEmpty(entry, "DN")
		name := firstOrEmpty(entry, "cn")
		guid := firstOrEmpty(entry, "objectGUID")

		if name == "" {
			name = dn
		}

		dsid := domainSID

		props := map[string]any{
			"distinguishedname": dn,
			"domain":            strings.ToUpper(domain),
			"domainsid":         dsid,
			"name":              name + "@" + strings.ToUpper(domain),
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(entry, "whenCreated"),
			),
		}

		// Set ContainedBy if we found the container
		var containedBy *BHContainedBy
		if rootCAContainerGUID != nil {
			containedBy = &BHContainedBy{
				ObjectIdentifier: *rootCAContainerGUID,
				ObjectType:       "Container",
			}
		}

		rootObj := BHRootCA{
			ObjectID:       guid,
			Properties:     props,
			DomainSID:      &dsid,
			Aces:           []BHAce{},
			IsDeleted:      false,
			IsACLProtected: false,
			ContainedBy:    containedBy,
		}
		out = append(out, rootObj)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "rootcas",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectNTAuthStoresBloodHound(
	baseDN string,
) (any, error) {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	filter := "(cn=NTAuthCertificates)"
	attrs := []string{
		"objectGUID", "cn", "distinguishedName", "whenCreated",
	}
	res, err := c.getAllResults(2, filter, attrs, pkiBaseDN)
	if err != nil {
		// Return empty result instead of error if no entries found
		return map[string]any{
			"data": []BHNTAuthStore{},
			"meta": map[string]any{
				"methods": 0,
				"type":    "ntauthstores",
				"count":   0,
				"version": 5,
			},
		}, nil
	}

	var out []BHNTAuthStore
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)
	pkiContainerGUID := c.getPKIContainerGUID(baseDN)

	for _, entry := range res {
		dn := firstOrEmpty(entry, "DN")
		name := firstOrEmpty(entry, "cn")
		guid := firstOrEmpty(entry, "objectGUID")

		if name == "" {
			name = dn
		}

		dsid := domainSID

		props := map[string]any{
			"distinguishedname": dn,
			"domain":            strings.ToUpper(domain),
			"domainsid":         dsid,
			"name":              name + "@" + strings.ToUpper(domain),
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(entry, "whenCreated"),
			),
		}

		// Set ContainedBy to Public Key Services container
		var containedBy *BHContainedBy
		if pkiContainerGUID != nil {
			containedBy = &BHContainedBy{
				ObjectIdentifier: *pkiContainerGUID,
				ObjectType:       "Container",
			}
		}

		ntObj := BHNTAuthStore{
			ObjectID:       guid,
			Properties:     props,
			DomainSID:      &dsid,
			Aces:           []BHAce{},
			IsDeleted:      false,
			IsACLProtected: false,
			ContainedBy:    containedBy,
		}
		out = append(out, ntObj)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "ntauthstores",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectIssuancePoliciesBloodHound(
	baseDN string,
) (any, error) {
	pkiBaseDN := buildPKIConfigDN(baseDN)
	// Issuance Policies are typically under CN=OID
	oidContainerDN := "CN=OID," + pkiBaseDN
	attrs := []string{
		"objectGUID", "cn", "displayName", "distinguishedName", "whenCreated",
		"msPKI-OIDCertTemplate-OID",
	}
	// Search in OID container for issuance policy objects
	res, err := c.getAllResults(
		1,
		"(displayName=*Assurance*)",
		attrs,
		oidContainerDN,
	)
	if err != nil || len(res) == 0 {
		// Try searching for msPKI-IssuancePolicy objectClass
		res, err = c.getAllResults(
			2,
			"(objectClass=msPKI-IssuancePolicy)",
			attrs,
			oidContainerDN,
		)
	}
	if err != nil || len(res) == 0 {
		// Last attempt: search whole PKI base
		res, err = c.getAllResults(
			2,
			"(objectClass=msPKI-IssuancePolicy)",
			attrs,
			pkiBaseDN,
		)
	}
	if err != nil {
		// Return empty result instead of error if no entries found
		return map[string]any{
			"data": []BHIssuancePolicy{},
			"meta": map[string]any{
				"methods": 0,
				"type":    "issuancepolicies",
				"count":   0,
				"version": 5,
			},
		}, nil
	}

	var out []BHIssuancePolicy
	domainSID := c.getDomainSID(baseDN)
	domain := extractDomainFromDN(baseDN)

	for _, entry := range res {
		dn := firstOrEmpty(entry, "DN")
		name := firstOrEmpty(entry, "displayName")
		if name == "" {
			name = firstOrEmpty(entry, "cn")
		}
		guid := firstOrEmpty(entry, "objectGUID")

		if name == "" {
			name = dn
		}

		props := map[string]any{
			"distinguishedname": dn,
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"name":              name + "@" + strings.ToUpper(domain),
			"displayname": toStringOrNil(
				firstOrEmpty(entry, "displayName"),
			),
			"whencreated": parseLDAPGeneralizedTime(
				firstOrEmpty(entry, "whenCreated"),
			),
			"certtemplateoid": toStringOrNil(
				firstOrEmpty(entry, "msPKI-OIDCertTemplate-OID"),
			),
		}

		policyObj := BHIssuancePolicy{
			ObjectID:       guid,
			Properties:     props,
			GroupLink:      nil,
			Aces:           []BHAce{},
			IsDeleted:      false,
			IsACLProtected: false,
			ContainedBy:    nil,
		}
		out = append(out, policyObj)
	}

	return map[string]any{
		"data": out,
		"meta": map[string]any{
			"methods": 0,
			"type":    "issuancepolicies",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}
