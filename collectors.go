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
	ObjectID        string                 `json:"ObjectId"`
	Properties      map[string]interface{} `json:"Properties"`
	Aces            []BHAce                `json:"Aces,omitempty"`
	GroupMembership []string               `json:"GroupMembership,omitempty"`
}

type BHComputer struct {
	ObjectID        string                 `json:"ObjectId"`
	Properties      map[string]interface{} `json:"Properties"`
	Aces            []BHAce                `json:"Aces,omitempty"`
	GroupMembership []string               `json:"GroupMembership,omitempty"`
	LocalAdmins     []string               `json:"LocalAdmins,omitempty"`
	Sessions        []string               `json:"Sessions,omitempty"`
}

type BHGroup struct {
	ObjectID   string                 `json:"ObjectId"`
	Properties map[string]interface{} `json:"Properties"`
	Aces       []BHAce                `json:"Aces,omitempty"`
	Members    []BHMember             `json:"Members,omitempty"`
}

type BHDomain struct {
	ObjectID   string                 `json:"ObjectId"`
	Properties map[string]interface{} `json:"Properties"`
	Aces       []BHAce                `json:"Aces,omitempty"`
}

type BHMember struct {
	ObjectID   string `json:"ObjectId"`
	ObjectType string `json:"ObjectType"`
}

type BHAce struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	AceType       string `json:"AceType"`
	Inherited     bool   `json:"Inherited"`
}

type BHMetadata struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
}

// CollectSharpHound runs LDAP collectors and writes BloodHound-compatible JSON into a zip archive.
func (c *Conn) CollectSharpHound(collectors []string, outputPath string, baseDN string, dryRun bool) (string, error) {
	supported := map[string]func(string) (interface{}, error){
		"users":     c.collectUsersBloodHound,
		"computers": c.collectComputersBloodHound,
		"groups":    c.collectGroupsBloodHound,
		"domains":   c.collectDomainsBloodHound,
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
		outputPath = fmt.Sprintf("sharphound-%s.zip", time.Now().Format("20060102-150405"))
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
	attrs := []string{"distinguishedName", "sAMAccountName", "userPrincipalName", "objectSid", "displayName", "mail", "memberOf", "userAccountControl"}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	out := []BHUser{}
	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		sid := firstOrEmpty(e, "objectSid")
		if sid == "" {
			continue // Skip if no SID
		}

		props := map[string]interface{}{
			"displayname":       firstOrEmpty(e, "displayName"),
			"mail":              firstOrEmpty(e, "mail"),
			"samaccountname":    firstOrEmpty(e, "sAMAccountName"),
			"userprincipalname": firstOrEmpty(e, "userPrincipalName"),
			"domain":            extractDomainFromDN(dn),
		}

		user := BHUser{
			ObjectID:        sid,
			Properties:      props,
			GroupMembership: e["memberOf"],
		}
		out = append(out, user)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"version": "4",
			"type":    "users",
		},
	}, nil
}

func (c *Conn) collectComputersBloodHound(baseDN string) (interface{}, error) {
	filter := "(&(objectCategory=computer))"
	attrs := []string{"distinguishedName", "sAMAccountName", "dNSHostName", "operatingSystem", "objectSid", "memberOf"}
	res, err := c.getAllResults(2, filter, attrs, baseDN)
	if err != nil {
		return nil, err
	}

	out := []BHComputer{}
	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		sid := firstOrEmpty(e, "objectSid")
		if sid == "" {
			continue
		}

		dnsHostName := firstOrEmpty(e, "dNSHostName")
		samAccountName := firstOrEmpty(e, "sAMAccountName")
		if samAccountName != "" && strings.HasSuffix(samAccountName, "$") {
			samAccountName = samAccountName[:len(samAccountName)-1] // Remove trailing $
		}

		props := map[string]interface{}{
			"name":            samAccountName,
			"dnshostname":     dnsHostName,
			"operatingsystem": firstOrEmpty(e, "operatingSystem"),
			"domain":          extractDomainFromDN(dn),
		}

		computer := BHComputer{
			ObjectID:        sid,
			Properties:      props,
			GroupMembership: e["memberOf"],
		}
		out = append(out, computer)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"version": "4",
			"type":    "computers",
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
	for _, e := range res {
		dn := firstOrEmpty(e, "DN")
		sid := firstOrEmpty(e, "objectSid")
		if sid == "" {
			continue
		}

		members := []BHMember{}
		for _, memberDN := range e["member"] {
			members = append(members, BHMember{
				ObjectID:   memberDN,
				ObjectType: "User", // Simplified; could parse DN to determine type
			})
		}

		props := map[string]interface{}{
			"name":        firstOrEmpty(e, "sAMAccountName"),
			"description": firstOrEmpty(e, "description"),
			"domain":      extractDomainFromDN(dn),
		}

		group := BHGroup{
			ObjectID:   sid,
			Properties: props,
			Members:    members,
		}
		out = append(out, group)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"version": "4",
			"type":    "groups",
		},
	}, nil
}

func (c *Conn) collectDomainsBloodHound(baseDN string) (interface{}, error) {
	filter := "(objectClass=domain)"
	attrs := []string{"distinguishedName", "objectSid", "name"}
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
		props := map[string]interface{}{
			"name":   extractDomainFromDN(dn),
			"domain": extractDomainFromDN(dn),
		}

		domain := BHDomain{
			ObjectID:   sid,
			Properties: props,
		}
		out = append(out, domain)
	}

	return map[string]interface{}{
		"data": out,
		"meta": map[string]interface{}{
			"version": "4",
			"type":    "domains",
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
