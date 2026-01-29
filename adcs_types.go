package ldaptickler

// ADCS Certificate Template Flag Constants
// Reference: MS-CRTD - Certificate Templates Data Structure
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/

const (
	// msPKI-Certificate-Name-Flag constants
	CTFlagEnrolleeSuppliesSubject        = 0x00000001
	CTFlagEnrolleeSuppliesSubjectAltName = 0x00010000
	CTFlagSubjectRequireDirectoryPath    = 0x80000000
	CTFlagSubjectRequireCommonName       = 0x40000000
	CTFlagSubjectRequireEmail            = 0x20000000
	CTFlagSubjectRequireDNSAsCN          = 0x10000000
	CTFlagSubjectAltRequireUPN           = 0x02000000
	CTFlagSubjectAltRequireEmail         = 0x01000000
	CTFlagSubjectAltRequireSPN           = 0x00800000
	CTFlagSubjectAltRequireDirectoryGUID = 0x01000000
	CTFlagSubjectAltRequireDNS           = 0x08000000
	CTFlagSubjectAltRequireDomainDNS     = 0x00400000

	// msPKI-Enrollment-Flag constants
	CTFlagIncludeSymmetricAlgorithms       = 0x00000001
	CTFlagPendAllRequests                  = 0x00000002
	CTFlagPublishToKRAContainer            = 0x00000004
	CTFlagPublishToDS                      = 0x00000008
	CTFlagAutoEnrollmentCheckUserDSCert    = 0x00000010
	CTFlagAutoEnrollment                   = 0x00000020
	CTFlagPreviousApprovalValidateReenroll = 0x00000040
	CTFlagUserInteractionRequired          = 0x00000100
	CTFlagRemoveInvalidCertFromStore       = 0x00000400
	CTFlagAllowEnrollOnBehalfOf            = 0x00000800
	CTFlagAddOCSPNoCheck                   = 0x00001000
	CTFlagEnableKeyReuseOnNTTokenFull      = 0x00002000
	CTFlagNoRevocationInfoInCerts          = 0x00004000
	CTFlagIncludeBasicConstraintsForEE     = 0x00008000
	CTFlagIssuancePoliciesFromRequest      = 0x00020000
	CTFlagSkipAutoRenewal                  = 0x00040000
	CTFlagNoSecurityExtension              = 0x00080000 // ESC9

	// msPKI-Private-Key-Flag constants
	CTFlagRequirePrivateKeyArchival     = 0x00000001
	CTFlagExportableKey                 = 0x00000010
	CTFlagStrongKeyProtectionRequired   = 0x00000020
	CTFlagRequireAlternateSignatureAlgo = 0x00000040
	CTFlagRequireSameKeyRenewal         = 0x00000080
	CTFlagUseLegacyProvider             = 0x00000100
	CTFlagAttestNone                    = 0x00000000
	CTFlagAttestRequired                = 0x00002000
	CTFlagAttestPreferred               = 0x00001000
	CTFlagHelloLogonKey                 = 0x00200000

	// Well-known EKU OIDs
	OIDClientAuthentication    = "1.3.6.1.5.5.7.3.2"
	OIDSmartCardLogon          = "1.3.6.1.4.1.311.20.2.2"
	OIDPKINITClientAuth        = "1.3.6.1.5.2.3.4"
	OIDAnyPurpose              = "2.5.29.37.0"
	OIDCertificateRequestAgent = "1.3.6.1.4.1.311.20.2.1"
	OIDServerAuth              = "1.3.6.1.5.5.7.3.1"

	// Certificate enrollment extended rights GUIDs
	RightCertificateEnrollment     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	RightCertificateAutoEnrollment = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
)

// CertTemplate holds parsed certificate template data with security analysis
type CertTemplate struct {
	Name          string
	DisplayName   string
	DN            string
	ObjectGUID    string
	SchemaVersion int
	OID           string

	// Flag values from LDAP
	EnrollmentFlag      uint32
	CertificateNameFlag uint32
	PrivateKeyFlag      uint32

	// EKUs and policies
	EKUs                  []string
	ApplicationPolicies   []string
	RASignaturesRequired  int
	RAApplicationPolicies []string
	IssuancePolicies      []string

	// Validity periods
	ValidityPeriod string
	RenewalPeriod  string

	// Security analysis
	EnrollmentPrincipals []EnrollmentPermission
	ObjectControllers    []ObjectPermission
	OwnerSID             string

	// Computed properties
	ClientAuthEnabled          bool
	EnrolleeSuppliesSubject    bool
	ManagerApprovalRequired    bool
	AuthorizedSignaturesNeeded int
	NoSecurityExtension        bool

	// ESC vulnerabilities
	ESCVulnerabilities []ESCVulnerability
}

// EnrollmentPermission represents who can enroll in a template
type EnrollmentPermission struct {
	PrincipalSID  string
	PrincipalName string
	PrincipalType string // User, Group, Computer
	CanEnroll     bool
	CanAutoEnroll bool
}

// ObjectPermission represents dangerous object-level permissions (ESC4)
type ObjectPermission struct {
	PrincipalSID  string
	PrincipalName string
	PrincipalType string
	Permission    string // GenericAll, WriteDacl, WriteOwner, WriteProperty
}

// ESCVulnerability represents a detected vulnerability
type ESCVulnerability struct {
	Name        string // ESC1, ESC2, etc.
	Description string
	Principals  []string // Who can exploit this
}

// EnterpriseCA holds CA configuration and permissions
type EnterpriseCA struct {
	Name                  string
	DN                    string
	DNSHostname           string
	ObjectGUID            string
	CertificateTemplates  []string // Templates published by this CA
	CASecurityPermissions []CAPermission

	// Flags
	UserSpecifiedSAN bool // EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)

	// ESC vulnerabilities
	ESCVulnerabilities []ESCVulnerability
}

// CAPermission for ESC7 detection
type CAPermission struct {
	PrincipalSID  string
	PrincipalName string
	ManageCA      bool
	ManageCerts   bool
	Enroll        bool
}

// ADCSEnumResult holds complete ADCS enumeration results
type ADCSEnumResult struct {
	CAs        []EnterpriseCA
	Templates  []CertTemplate
	DomainSID  string
	DomainName string
}

// Helper functions for flag checking

// HasClientAuthEKU checks if the template allows client authentication
func (t *CertTemplate) HasClientAuthEKU() bool {
	authEKUs := []string{
		OIDClientAuthentication,
		OIDSmartCardLogon,
		OIDPKINITClientAuth,
		OIDAnyPurpose,
	}

	for _, eku := range t.EKUs {
		for _, authEKU := range authEKUs {
			if eku == authEKU {
				return true
			}
		}
	}

	// Empty EKU list can also be dangerous (SubCA)
	return len(t.EKUs) == 0
}

// HasAnyPurposeEKU checks for Any Purpose or no EKUs
func (t *CertTemplate) HasAnyPurposeEKU() bool {
	for _, eku := range t.EKUs {
		if eku == OIDAnyPurpose {
			return true
		}
	}
	return false
}

// HasCertRequestAgentEKU checks for Certificate Request Agent EKU (ESC3)
func (t *CertTemplate) HasCertRequestAgentEKU() bool {
	for _, eku := range t.EKUs {
		if eku == OIDCertificateRequestAgent {
			return true
		}
	}
	return false
}

// IsVulnerableToESC1 checks ESC1 conditions
func (t *CertTemplate) IsVulnerableToESC1() bool {
	return t.EnrolleeSuppliesSubject &&
		t.HasClientAuthEKU() &&
		!t.ManagerApprovalRequired &&
		t.AuthorizedSignaturesNeeded == 0 &&
		len(t.EnrollmentPrincipals) > 0
}

// IsVulnerableToESC2 checks ESC2 conditions (Any Purpose or SubCA)
func (t *CertTemplate) IsVulnerableToESC2() bool {
	return (t.HasAnyPurposeEKU() || len(t.EKUs) == 0) &&
		!t.ManagerApprovalRequired &&
		len(t.EnrollmentPrincipals) > 0
}

// IsVulnerableToESC3 checks ESC3 conditions (Certificate Request Agent)
func (t *CertTemplate) IsVulnerableToESC3() bool {
	return t.HasCertRequestAgentEKU() &&
		!t.ManagerApprovalRequired &&
		len(t.EnrollmentPrincipals) > 0
}

// IsVulnerableToESC4 checks ESC4 conditions (dangerous ACLs)
func (t *CertTemplate) IsVulnerableToESC4() bool {
	return len(t.ObjectControllers) > 0
}

// IsVulnerableToESC9 checks ESC9 conditions (No Security Extension)
func (t *CertTemplate) IsVulnerableToESC9() bool {
	return t.NoSecurityExtension && t.HasClientAuthEKU()
}
