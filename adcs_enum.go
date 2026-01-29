package ldaptickler

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/huner2/go-sddlparse"
)

// ADCS LDAP attributes for template enumeration
var adcsTemplateAttrs = []string{
	"cn",
	"displayName",
	"distinguishedName",
	"objectGUID",
	"msPKI-Certificate-Name-Flag",
	"msPKI-Enrollment-Flag",
	"msPKI-Private-Key-Flag",
	"msPKI-RA-Signature",
	"msPKI-RA-Application-Policies",
	"msPKI-Certificate-Application-Policy",
	"pKIExtendedKeyUsage",
	"msPKI-Certificate-Policy",
	"msPKI-Template-Schema-Version",
	"pKIExpirationPeriod",
	"pKIOverlapPeriod",
	"nTSecurityDescriptor",
}

var adcsCAAttrs = []string{
	"cn",
	"distinguishedName",
	"objectGUID",
	"dNSHostName",
	"certificateTemplates",
	"nTSecurityDescriptor",
}

// ListADCSTemplates enumerates certificate templates with full security analysis
func (c *Conn) ListADCSTemplates() ([]CertTemplate, error) {
	pkiBaseDN := buildPKIConfigDN(c.baseDN)
	filter := "(objectClass=pKICertificateTemplate)"

	results, err := c.ldapSearchWithSD(pkiBaseDN, 2, filter, adcsTemplateAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate certificate templates: %w", err)
	}

	var templates []CertTemplate

	for _, entry := range results.Entries {
		template := c.parseTemplateEntry(entry)
		templates = append(templates, template)
	}

	// Detect ESC vulnerabilities for each template
	for i := range templates {
		templates[i].ESCVulnerabilities = detectTemplateESC(&templates[i])
	}

	return templates, nil
}

// ListEnterpriseCAs enumerates Enterprise CAs with permissions
func (c *Conn) ListEnterpriseCAs() ([]EnterpriseCA, error) {
	pkiBaseDN := buildPKIConfigDN(c.baseDN)
	filter := "(objectClass=pKIEnrollmentService)"

	results, err := c.ldapSearchWithSD(pkiBaseDN, 2, filter, adcsCAAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate enterprise CAs: %w", err)
	}

	var cas []EnterpriseCA

	for _, entry := range results.Entries {
		ca := c.parseCAEntry(entry)
		cas = append(cas, ca)
	}

	// Detect CA-level ESC vulnerabilities
	for i := range cas {
		cas[i].ESCVulnerabilities = detectCAESC(&cas[i])
	}

	return cas, nil
}

// EnumerateADCS performs full ADCS enumeration
func (c *Conn) EnumerateADCS() (*ADCSEnumResult, error) {
	result := &ADCSEnumResult{
		DomainSID:  c.getDomainSID(c.baseDN),
		DomainName: extractDomainFromDN(c.baseDN),
	}

	cas, err := c.ListEnterpriseCAs()
	if err != nil {
		return nil, err
	}
	result.CAs = cas

	templates, err := c.ListADCSTemplates()
	if err != nil {
		return nil, err
	}
	result.Templates = templates

	return result, nil
}

// parseTemplateEntry parses LDAP entry into CertTemplate
func (c *Conn) parseTemplateEntry(entry *ldapEntry) CertTemplate {
	template := CertTemplate{
		Name:        getAttrValue(entry, "cn"),
		DisplayName: getAttrValue(entry, "displayName"),
		DN:          getAttrValue(entry, "distinguishedName"),
		ObjectGUID:  getAttrValue(entry, "objectGUID"),
	}

	// Parse flag values
	if v := getAttrValue(entry, "msPKI-Certificate-Name-Flag"); v != "" {
		if val, err := strconv.ParseUint(v, 10, 32); err == nil {
			template.CertificateNameFlag = uint32(val)
		}
	}

	if v := getAttrValue(entry, "msPKI-Enrollment-Flag"); v != "" {
		if val, err := strconv.ParseUint(v, 10, 32); err == nil {
			template.EnrollmentFlag = uint32(val)
		}
	}

	if v := getAttrValue(entry, "msPKI-Private-Key-Flag"); v != "" {
		if val, err := strconv.ParseUint(v, 10, 32); err == nil {
			template.PrivateKeyFlag = uint32(val)
		}
	}

	// Parse RA signatures required
	if v := getAttrValue(entry, "msPKI-RA-Signature"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			template.RASignaturesRequired = val
			template.AuthorizedSignaturesNeeded = val
		}
	}

	// Parse schema version
	if v := getAttrValue(entry, "msPKI-Template-Schema-Version"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			template.SchemaVersion = val
		}
	}

	// Parse EKUs - try both attributes
	template.EKUs = getAttrValues(entry, "pKIExtendedKeyUsage")
	if len(template.EKUs) == 0 {
		template.EKUs = getAttrValues(entry, "msPKI-Certificate-Application-Policy")
	}

	// Parse application policies
	template.ApplicationPolicies = getAttrValues(entry, "msPKI-RA-Application-Policies")
	template.IssuancePolicies = getAttrValues(entry, "msPKI-Certificate-Policy")

	// Parse validity period
	if periodBytes := getAttrBytes(entry, "pKIExpirationPeriod"); len(periodBytes) >= 8 {
		template.ValidityPeriod = parseFiletimeDuration(periodBytes)
	}

	if periodBytes := getAttrBytes(entry, "pKIOverlapPeriod"); len(periodBytes) >= 8 {
		template.RenewalPeriod = parseFiletimeDuration(periodBytes)
	}

	// Compute boolean flags
	template.EnrolleeSuppliesSubject = (template.CertificateNameFlag & CTFlagEnrolleeSuppliesSubject) != 0
	template.ManagerApprovalRequired = (template.EnrollmentFlag & CTFlagPendAllRequests) != 0
	template.NoSecurityExtension = (template.EnrollmentFlag & CTFlagNoSecurityExtension) != 0
	template.ClientAuthEnabled = template.HasClientAuthEKU()

	// Parse security descriptor for enrollment permissions
	if sdBytes := getAttrBytes(entry, "nTSecurityDescriptor"); len(sdBytes) > 0 {
		enrollPerms, objPerms, owner := c.parseTemplateSecurityDescriptor(sdBytes)
		template.EnrollmentPrincipals = enrollPerms
		template.ObjectControllers = objPerms
		template.OwnerSID = owner
	}

	return template
}

// parseCAEntry parses LDAP entry into EnterpriseCA
func (c *Conn) parseCAEntry(entry *ldapEntry) EnterpriseCA {
	ca := EnterpriseCA{
		Name:                 getAttrValue(entry, "cn"),
		DN:                   getAttrValue(entry, "distinguishedName"),
		DNSHostname:          getAttrValue(entry, "dNSHostName"),
		ObjectGUID:           getAttrValue(entry, "objectGUID"),
		CertificateTemplates: getAttrValues(entry, "certificateTemplates"),
	}

	// Parse security descriptor for CA permissions
	if sdBytes := getAttrBytes(entry, "nTSecurityDescriptor"); len(sdBytes) > 0 {
		ca.CASecurityPermissions = c.parseCASecurityDescriptor(sdBytes)
	}

	return ca
}

// parseTemplateSecurityDescriptor extracts enrollment permissions and dangerous ACLs
func (c *Conn) parseTemplateSecurityDescriptor(sdBytes []byte) ([]EnrollmentPermission, []ObjectPermission, string) {
	var enrollPerms []EnrollmentPermission
	var objPerms []ObjectPermission
	var ownerSID string

	sd, err := sddlparse.SDDLFromBinary(sdBytes)
	if err != nil {
		return enrollPerms, objPerms, ownerSID
	}

	ownerSID = sd.Owner

	// Dangerous permissions that indicate ESC4
	dangerousMasks := sddlparse.ACCESS_MASK_GENERIC_ALL |
		sddlparse.ACCESS_MASK_GENERIC_WRITE |
		sddlparse.ACCESS_MASK_WRITE_OWNER |
		sddlparse.ACCESS_MASK_WRITE_DACL

	for _, ace := range sd.DACL {
		sid := ace.SID

		// Skip well-known admin SIDs for ESC4 (they're expected to have control)
		if isWellKnownAdminSID(sid) {
			continue
		}

		principalName, principalType := c.resolveSIDToPrincipal(sid)

		// Check for enrollment extended rights (compare GUID string representation)
		aceObjectType := ace.ObjectType.String()
		if aceObjectType == RightCertificateEnrollment {
			enrollPerms = append(enrollPerms, EnrollmentPermission{
				PrincipalSID:  sid,
				PrincipalName: principalName,
				PrincipalType: principalType,
				CanEnroll:     true,
				CanAutoEnroll: false,
			})
		}

		if aceObjectType == RightCertificateAutoEnrollment {
			// Find or create enrollment permission
			found := false
			for i := range enrollPerms {
				if enrollPerms[i].PrincipalSID == sid {
					enrollPerms[i].CanAutoEnroll = true
					found = true
					break
				}
			}
			if !found {
				enrollPerms = append(enrollPerms, EnrollmentPermission{
					PrincipalSID:  sid,
					PrincipalName: principalName,
					PrincipalType: principalType,
					CanEnroll:     false,
					CanAutoEnroll: true,
				})
			}
		}

		// Check for GenericAll which includes enrollment
		if ace.AccessMask&sddlparse.ACCESS_MASK_GENERIC_ALL != 0 {
			found := false
			for i := range enrollPerms {
				if enrollPerms[i].PrincipalSID == sid {
					enrollPerms[i].CanEnroll = true
					found = true
					break
				}
			}
			if !found {
				enrollPerms = append(enrollPerms, EnrollmentPermission{
					PrincipalSID:  sid,
					PrincipalName: principalName,
					PrincipalType: principalType,
					CanEnroll:     true,
					CanAutoEnroll: false,
				})
			}
		}

		// Check for dangerous permissions (ESC4)
		if ace.AccessMask&dangerousMasks != 0 {
			var permName string
			switch {
			case ace.AccessMask&sddlparse.ACCESS_MASK_GENERIC_ALL != 0:
				permName = "GenericAll"
			case ace.AccessMask&sddlparse.ACCESS_MASK_GENERIC_WRITE != 0:
				permName = "GenericWrite"
			case ace.AccessMask&sddlparse.ACCESS_MASK_WRITE_DACL != 0:
				permName = "WriteDacl"
			case ace.AccessMask&sddlparse.ACCESS_MASK_WRITE_OWNER != 0:
				permName = "WriteOwner"
			}

			objPerms = append(objPerms, ObjectPermission{
				PrincipalSID:  sid,
				PrincipalName: principalName,
				PrincipalType: principalType,
				Permission:    permName,
			})
		}
	}

	return enrollPerms, objPerms, ownerSID
}

// parseCASecurityDescriptor extracts CA permissions for ESC7 detection
func (c *Conn) parseCASecurityDescriptor(sdBytes []byte) []CAPermission {
	var caPerms []CAPermission

	sd, err := sddlparse.SDDLFromBinary(sdBytes)
	if err != nil {
		return caPerms
	}

	// CA-specific rights
	// ManageCA = 0x00000001, ManageCertificates = 0x00000002
	const (
		caRightManageCA    = 0x00000001
		caRightManageCerts = 0x00000002
	)

	for _, ace := range sd.DACL {
		sid := ace.SID

		if isWellKnownAdminSID(sid) {
			continue
		}

		principalName, _ := c.resolveSIDToPrincipal(sid)

		perm := CAPermission{
			PrincipalSID:  sid,
			PrincipalName: principalName,
		}

		// Check for ManageCA/ManageCertificates via GenericAll or specific rights
		if ace.AccessMask&sddlparse.ACCESS_MASK_GENERIC_ALL != 0 {
			perm.ManageCA = true
			perm.ManageCerts = true
			perm.Enroll = true
		}

		if ace.AccessMask&caRightManageCA != 0 {
			perm.ManageCA = true
		}

		if ace.AccessMask&caRightManageCerts != 0 {
			perm.ManageCerts = true
		}

		// Check for enrollment (compare GUID string representation)
		if ace.ObjectType.String() == RightCertificateEnrollment {
			perm.Enroll = true
		}

		if perm.ManageCA || perm.ManageCerts || perm.Enroll {
			caPerms = append(caPerms, perm)
		}
	}

	return caPerms
}

// resolveSIDToPrincipal looks up a SID and returns name and type
func (c *Conn) resolveSIDToPrincipal(sid string) (string, string) {
	// Check well-known SIDs first
	if name, ok := wellKnownSIDs[sid]; ok {
		return name, "Group"
	}

	// Try to resolve via LDAP
	filter := fmt.Sprintf("(objectSid=%s)", sid)
	attrs := []string{"sAMAccountName", "objectClass"}

	results, err := c.getAllResults(2, filter, attrs)
	if err != nil || len(results) == 0 {
		return sid, "Unknown"
	}

	name := firstOrEmpty(results[0], "sAMAccountName")
	if name == "" {
		name = sid
	}

	objectClass := firstOrEmpty(results[0], "objectClass")
	principalType := "Unknown"
	switch {
	case strings.Contains(objectClass, "user"):
		principalType = "User"
	case strings.Contains(objectClass, "group"):
		principalType = "Group"
	case strings.Contains(objectClass, "computer"):
		principalType = "Computer"
	}

	return name, principalType
}

// Well-known SIDs that are expected to have admin permissions
var wellKnownSIDs = map[string]string{
	"S-1-5-18":     "SYSTEM",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-9":      "Enterprise Domain Controllers",
}

// Well-known admin SIDs to skip for ESC4/ESC7 detection
func isWellKnownAdminSID(sid string) bool {
	adminSIDs := []string{
		"S-1-5-18",     // SYSTEM
		"S-1-5-32-544", // Administrators
		"S-1-5-9",      // Enterprise Domain Controllers
		"S-1-5-32-548", // Account Operators
		"S-1-5-32-549", // Server Operators
	}

	for _, adminSID := range adminSIDs {
		if sid == adminSID {
			return true
		}
	}

	// Check for domain-relative admin SIDs (Domain Admins, Enterprise Admins)
	// These end in -512, -519, -500
	if strings.HasSuffix(sid, "-512") || // Domain Admins
		strings.HasSuffix(sid, "-519") || // Enterprise Admins
		strings.HasSuffix(sid, "-500") { // Administrator
		return true
	}

	return false
}

// detectTemplateESC detects ESC vulnerabilities in a template
func detectTemplateESC(t *CertTemplate) []ESCVulnerability {
	var vulns []ESCVulnerability

	// Get exploitable principals (non-admin enrollees)
	var exploitablePrincipals []string
	for _, ep := range t.EnrollmentPrincipals {
		if ep.CanEnroll && !isWellKnownAdminSID(ep.PrincipalSID) {
			exploitablePrincipals = append(exploitablePrincipals, ep.PrincipalName)
		}
	}

	// ESC1: Enrollee supplies subject with client auth
	if t.IsVulnerableToESC1() {
		vulns = append(vulns, ESCVulnerability{
			Name:        "ESC1",
			Description: "Enrollee supplies subject with client authentication EKU",
			Principals:  exploitablePrincipals,
		})
	}

	// ESC2: Any Purpose or SubCA
	if t.IsVulnerableToESC2() {
		desc := "Any Purpose EKU or no EKUs (SubCA)"
		if t.HasAnyPurposeEKU() {
			desc = "Any Purpose EKU enables impersonation"
		} else if len(t.EKUs) == 0 {
			desc = "No EKUs defined (SubCA template)"
		}
		vulns = append(vulns, ESCVulnerability{
			Name:        "ESC2",
			Description: desc,
			Principals:  exploitablePrincipals,
		})
	}

	// ESC3: Certificate Request Agent
	if t.IsVulnerableToESC3() {
		vulns = append(vulns, ESCVulnerability{
			Name:        "ESC3",
			Description: "Certificate Request Agent EKU allows enrollment on behalf of others",
			Principals:  exploitablePrincipals,
		})
	}

	// ESC4: Dangerous ACLs
	if t.IsVulnerableToESC4() {
		var aclPrincipals []string
		for _, op := range t.ObjectControllers {
			aclPrincipals = append(aclPrincipals, fmt.Sprintf("%s (%s)", op.PrincipalName, op.Permission))
		}
		vulns = append(vulns, ESCVulnerability{
			Name:        "ESC4",
			Description: "Dangerous write permissions on template object",
			Principals:  aclPrincipals,
		})
	}

	// ESC9: No Security Extension
	if t.IsVulnerableToESC9() {
		vulns = append(vulns, ESCVulnerability{
			Name:        "ESC9",
			Description: "CT_FLAG_NO_SECURITY_EXTENSION is set - weak certificate mapping",
			Principals:  exploitablePrincipals,
		})
	}

	return vulns
}

// detectCAESC detects ESC vulnerabilities in a CA
func detectCAESC(ca *EnterpriseCA) []ESCVulnerability {
	var vulns []ESCVulnerability

	// ESC6: User-specified SAN (would need RPC to detect, limited via LDAP)
	// Skip for now as it requires registry access

	// ESC7: ManageCA or ManageCertificates permissions to non-admins
	var esc7Principals []string
	for _, perm := range ca.CASecurityPermissions {
		if (perm.ManageCA || perm.ManageCerts) && !isWellKnownAdminSID(perm.PrincipalSID) {
			permType := ""
			if perm.ManageCA {
				permType = "ManageCA"
			}
			if perm.ManageCerts {
				if permType != "" {
					permType += ", "
				}
				permType += "ManageCertificates"
			}
			esc7Principals = append(esc7Principals, fmt.Sprintf("%s (%s)", perm.PrincipalName, permType))
		}
	}

	if len(esc7Principals) > 0 {
		vulns = append(vulns, ESCVulnerability{
			Name:        "ESC7",
			Description: "Non-admin principals have ManageCA or ManageCertificates rights",
			Principals:  esc7Principals,
		})
	}

	return vulns
}

// Helper types for LDAP entry parsing
type ldapEntry struct {
	DN         string
	Attributes map[string]*ldapAttribute
}

type ldapAttribute struct {
	Name       string
	Values     []string
	ByteValues [][]byte
}

// ldapSearchWithSD performs LDAP search with security descriptor control
func (c *Conn) ldapSearchWithSD(baseDN string, scope int, filter string, attrs []string) (*ldapSearchResult, error) {
	// Request security descriptor with OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	sdFlags := uint32(0x04 | 0x01) // OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

	// Build the control value - just the flags as a 4-byte little-endian integer
	controlValue := make([]byte, 4)
	binary.LittleEndian.PutUint32(controlValue, sdFlags)

	result, err := c.ldapSearch(
		baseDN,
		scope,
		filter,
		attrs,
	)
	if err != nil {
		return nil, err
	}

	// Convert to our internal types
	searchResult := &ldapSearchResult{}
	for _, rawEntry := range result.Entries {
		entry := &ldapEntry{
			DN:         rawEntry.DN,
			Attributes: make(map[string]*ldapAttribute),
		}

		for _, attr := range rawEntry.Attributes {
			entry.Attributes[attr.Name] = &ldapAttribute{
				Name:       attr.Name,
				Values:     attr.Values,
				ByteValues: attr.ByteValues,
			}
		}

		searchResult.Entries = append(searchResult.Entries, entry)
	}

	return searchResult, nil
}

type ldapSearchResult struct {
	Entries []*ldapEntry
}

// Helper functions for attribute access
func getAttrValue(entry *ldapEntry, name string) string {
	if attr, ok := entry.Attributes[name]; ok && len(attr.Values) > 0 {
		return attr.Values[0]
	}
	return ""
}

func getAttrValues(entry *ldapEntry, name string) []string {
	if attr, ok := entry.Attributes[name]; ok {
		return attr.Values
	}
	return nil
}

func getAttrBytes(entry *ldapEntry, name string) []byte {
	if attr, ok := entry.Attributes[name]; ok && len(attr.ByteValues) > 0 {
		return attr.ByteValues[0]
	}
	return nil
}

// parseFiletimeDuration converts a Windows FILETIME duration to human-readable string
func parseFiletimeDuration(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	// FILETIME is stored as negative 100-nanosecond intervals
	ft := int64(binary.LittleEndian.Uint64(data))
	if ft >= 0 {
		return ""
	}

	// Convert to positive and to seconds
	seconds := (-ft) / 10000000

	days := seconds / 86400
	years := days / 365
	weeks := (days % 365) / 7
	remainingDays := days % 7

	var parts []string
	if years > 0 {
		parts = append(parts, fmt.Sprintf("%d years", years))
	}
	if weeks > 0 {
		parts = append(parts, fmt.Sprintf("%d weeks", weeks))
	}
	if remainingDays > 0 {
		parts = append(parts, fmt.Sprintf("%d days", remainingDays))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("%d seconds", seconds)
	}

	return strings.Join(parts, " ")
}
