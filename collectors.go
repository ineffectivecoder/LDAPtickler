package ldaptickler

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
	ObjectID          string                 `json:"ObjectIdentifier"`
	PrimaryGroupSID   *string                `json:"PrimaryGroupSID"`
	AllowedToDelegate []string               `json:"AllowedToDelegate"`
	Properties        map[string]interface{} `json:"Properties"`
	Aces              []BHAce                `json:"Aces"`
	SPNTargets        []string               `json:"SPNTargets"`
	HasSIDHistory     []string               `json:"HasSIDHistory"`
	IsDeleted         bool                   `json:"IsDeleted"`
}

type BHComputer struct {
	ObjectID           string                 `json:"ObjectIdentifier"`
	AllowedToAct       []string               `json:"AllowedToAct"`
	PrimaryGroupSID    *string                `json:"PrimaryGroupSID"`
	LocalAdmins        BHCollectionResult     `json:"LocalAdmins"`
	PSRemoteUsers      BHCollectionResult     `json:"PSRemoteUsers"`
	Properties         map[string]interface{} `json:"Properties"`
	RemoteDesktopUsers BHCollectionResult     `json:"RemoteDesktopUsers"`
	DcomUsers          BHCollectionResult     `json:"DcomUsers"`
	AllowedToDelegate  []string               `json:"AllowedToDelegate"`
	Sessions           BHCollectionResult     `json:"Sessions"`
	PrivilegedSessions BHCollectionResult     `json:"PrivilegedSessions"`
	RegistrySessions   BHCollectionResult     `json:"RegistrySessions"`
	Aces               []BHAce                `json:"Aces"`
	HasSIDHistory      []string               `json:"HasSIDHistory"`
	IsDeleted          bool                   `json:"IsDeleted"`
	Status             *string                `json:"Status"`
}

type BHCollectionResult struct {
	Collected     bool     `json:"Collected"`
	FailureReason *string  `json:"FailureReason"`
	Results       []string `json:"Results"`
}

type BHGroup struct {
	ObjectID   string                 `json:"ObjectIdentifier"`
	Properties map[string]interface{} `json:"Properties"`
	Members    []BHMember             `json:"Members"`
	Aces       []BHAce                `json:"Aces"`
	IsDeleted  bool                   `json:"IsDeleted"`
}

type BHDomain struct {
	ObjectID     string                 `json:"ObjectIdentifier"`
	Properties   map[string]interface{} `json:"Properties"`
	Trusts       []string               `json:"Trusts"`
	Aces         []BHAce                `json:"Aces"`
	Links        []string               `json:"Links"`
	ChildObjects []string               `json:"ChildObjects"`
	GPOChanges   BHGPOChanges           `json:"GPOChanges"`
	IsDeleted    bool                   `json:"IsDeleted"`
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
func (c *Conn) CollectBloodHound(collectors []string, outputPath string, baseDN string, dryRun bool) (string, error) {
	supported := map[string]func(string) (interface{}, error){
		"users":     c.collectUsersBloodHound,
		"computers": c.collectComputersBloodHound,
		"groups":    c.collectGroupsBloodHound,
		"domains":   c.collectDomainsBloodHound,
		"ous":       c.collectOUsBloodHound,
		"gpos":      c.collectGPOsBloodHound,
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
			return "", fmt.Errorf("collector %s failed: %w", name, err)
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
		outputPath = fmt.Sprintf("ldaptickler-%s.zip", time.Now().Format("20060102-150405"))
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

func (c *Conn) collectUsersBloodHound(baseDN string) (interface{}, error) {
	filter := "(&(objectCategory=person)(objectClass=user))"
	attrs := []string{
		"distinguishedName", "sAMAccountName", "userPrincipalName", "objectSid",
		"displayName", "mail", "memberOf", "userAccountControl", "primaryGroupID",
		"lastLogon", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName",
		"adminCount", "description", "title", "homeDirectory", "logonScript",
		"whenCreated", "nTSecurityDescriptor",
	}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
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

		props := map[string]interface{}{
			"name":                    userName,
			"domain":                  strings.ToUpper(domain),
			"domainsid":               domainSID,
			"distinguishedname":       dn,
			"unconstraineddelegation": uacProps["unconstraineddelegation"],
			"trustedtoauth":           uacProps["trustedtoauth"],
			"passwordnotreqd":         uacProps["passwordnotreqd"],
		}

		user := BHUser{
			ObjectID:          sid,
			PrimaryGroupSID:   primaryGroupSID,
			AllowedToDelegate: []string{},
			Properties:        props,
			Aces:              []BHAce{},
			SPNTargets:        []string{},
			HasSIDHistory:     []string{},
			IsDeleted:         false,
		}
		out = append(out, user)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"methods": 0,
			"type":    "users",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectComputersBloodHound(baseDN string) (interface{}, error) {
	filter := "(&(objectCategory=computer))"
	attrs := []string{"distinguishedName", "sAMAccountName", "dNSHostName", "operatingSystem", "objectSid", "memberOf", "userAccountControl", "primaryGroupID"}
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
			computerName = samAccountName + "@" + strings.ToUpper(domain)
		}

		props := map[string]interface{}{
			"name":                    computerName,
			"domainsid":               domainSID,
			"domain":                  strings.ToUpper(domain),
			"distinguishedname":       dn,
			"unconstraineddelegation": uacProps["unconstraineddelegation"],
			"enabled":                 uacProps["enabled"],
			"trustedtoauth":           uacProps["trustedtoauth"],
			"samaccountname":          samAccountName,
		}

		computer := BHComputer{
			ObjectID:           sid,
			AllowedToAct:       []string{},
			PrimaryGroupSID:    primaryGroupSID,
			LocalAdmins:        BHCollectionResult{Collected: false, FailureReason: nil, Results: []string{}},
			PSRemoteUsers:      BHCollectionResult{Collected: false, FailureReason: nil, Results: []string{}},
			Properties:         props,
			RemoteDesktopUsers: BHCollectionResult{Collected: false, FailureReason: nil, Results: []string{}},
			DcomUsers:          BHCollectionResult{Collected: false, FailureReason: nil, Results: []string{}},
			AllowedToDelegate:  []string{},
			Sessions:           BHCollectionResult{Collected: false, FailureReason: nil, Results: []string{}},
			PrivilegedSessions: BHCollectionResult{Collected: false, FailureReason: nil, Results: []string{}},
			RegistrySessions:   BHCollectionResult{Collected: false, FailureReason: nil, Results: []string{}},
			Aces:               []BHAce{},
			HasSIDHistory:      []string{},
			IsDeleted:          false,
			Status:             nil,
		}
		out = append(out, computer)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"methods": 0,
			"type":    "computers",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectGroupsBloodHound(baseDN string) (interface{}, error) {
	filter := "(objectCategory=group)"
	attrs := []string{"distinguishedName", "cn", "sAMAccountName", "member", "objectSid", "description"}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
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
			if strings.Contains(strings.ToLower(memberDN), "cn=computers") {
				objType = "Computer"
			} else if strings.Contains(strings.ToLower(memberDN), "objectClass=group") || c.isGroup(memberDN) {
				objType = "Group"
			}

			members = append(members, BHMember{
				ObjectIdentifier: memberSID,
				ObjectType:       objType,
			})
		}

		props := map[string]interface{}{
			"domain":            strings.ToUpper(domain),
			"domainsid":         domainSID,
			"highvalue":         false,
			"name":              firstOrEmpty(e, "sAMAccountName") + "@" + strings.ToUpper(domain),
			"distinguishedname": dn,
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

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"methods": 0,
			"type":    "groups",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectDomainsBloodHound(baseDN string) (interface{}, error) {
	filter := "(objectClass=domain)"
	attrs := []string{"distinguishedName", "objectSid", "name", "description", "whenCreated"}
	res, err := c.getAllResults(0, filter, attrs, baseDN) // Base scope for domain object
	if err != nil {
		return nil, err
	}

	out := []BHDomain{}
	for _, e := range res {
		sid := firstOrEmpty(e, "objectSid")
		if sid == "" {
			continue
		}

		dn := firstOrEmpty(e, "DN")
		domain := strings.ToUpper(extractDomainFromDN(dn))
		description := firstOrEmpty(e, "description")
		whenCreated := parseLDAPGeneralizedTime(firstOrEmpty(e, "whenCreated"))

		props := map[string]interface{}{
			"name":              domain,
			"domain":            domain,
			"domainsid":         sid,
			"distinguishedname": dn,
			"description":       description,
			"functionallevel":   "Unknown",
			"highvalue":         true,
			"whencreated":       whenCreated,
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
			IsDeleted: false,
		}
		out = append(out, domainObj)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"methods": 0,
			"type":    "domains",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectOUsBloodHound(baseDN string) (interface{}, error) {
	filter := "(objectClass=organizationalUnit)"
	attrs := []string{"distinguishedName", "objectGUID", "name", "gPLink"}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	out := []map[string]interface{}{}
	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		guid := firstOrEmpty(e, "objectGUID")
		if guid == "" {
			guid = dn
		}

		props := map[string]interface{}{
			"name":              firstOrEmpty(e, "name"),
			"domain":            extractDomainFromDN(dn),
			"distinguishedname": dn,
		}

		gpLink := firstOrEmpty(e, "gPLink")
		linkedGPOs := []string{}
		if gpLink != "" {
			parts := strings.Split(gpLink, "[LDAP://")
			for i := 1; i < len(parts); i++ {
				if idx := strings.Index(parts[i], ";"); idx > 0 {
					linkedGPOs = append(linkedGPOs, "LDAP://"+parts[i][:idx])
				}
			}
		}

		ou := map[string]interface{}{
			"ObjectIdentifier": guid,
			"Properties":       props,
		}
		if len(linkedGPOs) > 0 {
			ou["LinkedGPOs"] = linkedGPOs
		}
		out = append(out, ou)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"methods": 0,
			"type":    "ous",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectGPOsBloodHound(baseDN string) (interface{}, error) {
	filter := "(objectClass=groupPolicyContainer)"
	attrs := []string{"distinguishedName", "displayName", "name", "cn"}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	out := []map[string]interface{}{}
	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		name := firstOrEmpty(e, "displayName")
		if name == "" {
			name = firstOrEmpty(e, "cn")
		}

		props := map[string]interface{}{
			"name":   name,
			"domain": extractDomainFromDN(dn),
		}

		gpo := map[string]interface{}{
			"ObjectIdentifier": dn,
			"Properties":       props,
		}
		out = append(out, gpo)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"methods": 0,
			"type":    "gpos",
			"count":   len(out),
			"version": 5,
		},
	}, nil
}

func (c *Conn) collectTrustsBloodHound(baseDN string) (interface{}, error) {
	filter := "(objectClass=trustedDomain)"
	attrs := []string{"cn", "flatName", "distinguishedName", "objectSid", "trustAttributes", "trustDirection", "trustType"}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return map[string]interface{}{
			"data": []any{},
			"meta": map[string]interface{}{
				"methods": 0,
				"type":    "trusts",
				"count":   0,
				"version": 5,
			},
		}, nil
	}

	out := []map[string]interface{}{}
	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		cn := firstOrEmpty(e, "cn")

		props := map[string]interface{}{
			"name":            cn,
			"domain":          extractDomainFromDN(dn),
			"flatname":        firstOrEmpty(e, "flatName"),
			"trustattributes": firstOrEmpty(e, "trustAttributes"),
			"trustdirection":  firstOrEmpty(e, "trustDirection"),
			"trusttype":       firstOrEmpty(e, "trustType"),
		}

		trust := map[string]interface{}{
			"ObjectIdentifier": cn,
			"Properties":       props,
		}
		out = append(out, trust)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"methods": 0,
			"type":    "trusts",
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

// toNullableString converts empty string to nil, otherwise returns the string as interface{}
func toNullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// parseUAC decodes userAccountControl flags
func parseUAC(uacStr string) map[string]interface{} {
	result := map[string]interface{}{
		"unconstraineddelegation": false,
		"trustedtoauth":           false,
		"passwordnotreqd":         false,
		"enabled":                 true,
		"dontreqpreauth":          false,
		"pwdneverexpires":         false,
		"sensitive":               false,
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
	)

	result["unconstraineddelegation"] = (uac & UACTrustedForDelegation) != 0
	result["trustedtoauth"] = (uac & UACTrustedToAuthForDelegation) != 0
	result["passwordnotreqd"] = (uac & UACPasswordRequired) == 0
	result["enabled"] = (uac & UACAccountDisable) == 0
	result["dontreqpreauth"] = (uac & UACDontReqPreAuth) != 0
	result["pwdneverexpires"] = (uac & UACDontExpirePassword) != 0
	result["sensitive"] = (uac & UACNotDelegated) != 0

	return result
}

// parseWinFiletime converts Windows FILETIME to Unix timestamp
func parseWinFiletime(ftStr string) int64 {
	if ftStr == "" {
		return 0
	}
	var ft int64
	_, err := fmt.Sscanf(ftStr, "%d", &ft)
	if err != nil {
		return 0
	}
	// Windows FILETIME is 100-nanosecond intervals since Jan 1, 1601
	// Convert to Unix timestamp (seconds since Jan 1, 1970)
	if ft == 0 {
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
	_, err := fmt.Sscanf(timeStr[:14], "%4d%2d%2d%2d%2d%2d", &year, &month, &day, &hour, &min, &sec)
	if err != nil {
		return 0
	}

	// Create a time value
	t := time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)
	return t.Unix()
}

// getDomainSID retrieves the domain SID from the domain object
func (c *Conn) getDomainSID(baseDN string) string {
	filter := "(objectClass=domain)"
	attrs := []string{"objectSid"}
	res, err := c.getAllResults(0, filter, attrs, baseDN) // Base scope for domain object
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
	res, err := c.getAllResults(0, filter, attrs, dn) // Base scope search at the DN
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
