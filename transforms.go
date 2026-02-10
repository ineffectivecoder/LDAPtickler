package ldaptickler

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/huner2/go-sddlparse"
)

/*
	TODO

1. Refactor Search Results
2. Refactor LDAP Conn to be an interface
2.1. Implement interface with existing LDAP connections
3. Add ADWS!!!!!
*/
var (
	controlStringLookup = map[string]*ldap.ControlString{
		"msds-managedpassword": {
			ControlType: "1.2.840.113556.1.4.2064", // PolicyHints OID
			Criticality: false,                     // must be non-critical
			ControlValue: string(
				[]byte{0x30, 0x03, 0x02, 0x01, 0x01},
			), // raw BER: SEQUENCE(INT=1)
		},
		"ntsecuritydescriptor": {
			ControlType: "1.2.840.113556.1.4.801", // LDAP_SERVER_SD_FLAGS_OID
			Criticality: true,
			ControlValue: string(
				[]byte{0x30, 0x03, 0x02, 0x01, 0x07},
			),
		},
	}
	transformsLookup = map[string]func(bs [][]byte) []string{
		"dnsrecord": dnsRecordTransform,
		"msds-allowedtoactonbehalfofotheridentity": msdsAllowedToActOnBehalfOfOtherIdentityTransform,
		"msds-groupmsamembership":                  msdsGroupMSAMembershipTransform,
		"msds-managedpassword":                     msdsManagedPasswordTransform,
		"ntsecuritydescriptor":                     ntSecurityDescriptorTransform,
		"objectguid":                               objectGUIDTransform,
		"objectsid":                                objectSIDTransform,
	}
)

func dnsRecordTransform(bs [][]byte) []string {
	var data string
	values := []string{}

	for _, v := range bs {
		br := bytes.NewReader(v)
		// reading size
		b, err := byteReader(br, 2)
		if err != nil {
			values = append(
				values,
				fmt.Sprintf(
					"Invalid DNS record: %v",
					err,
				),
			)

			continue
		}

		datalength, n := binary.Uvarint(b)
		if n == 0 {
			values = append(
				values,
				fmt.Sprintf(
					"Could not read record type: %v",
					err,
				),
			)
			continue
		}
		// reading in rectype
		b, err = byteReader(br, 2)
		if err != nil {
			values = append(
				values,
				fmt.Sprintf(
					"Invalid DNS record: %v",
					err,
				),
			)

			continue
		}

		rectype := binary.LittleEndian.Uint64(
			append(b, []byte{0, 0, 0, 0, 0, 0}...),
		)
		if _, ok := recTypes[rectype]; !ok {
			values = append(
				values,
				fmt.Sprintf(
					"Unknown record type %d",
					rectype,
				),
			)

			continue
		}
		// read and skip version(1 byte), rank(1 byte) , flags (2 byte), serial(4 byte)
		_, err = byteReader(br, 8)
		if err != nil {
			values = append(
				values,
				fmt.Sprintf(
					"Invalid DNS record: %v",
					err,
				),
			)

			continue
		}
		// reading in TTL
		b, err = byteReader(br, 4)
		if err != nil {
			values = append(
				values,
				fmt.Sprintf(
					"Invalid DNS record: %v",
					err,
				),
			)

			continue
		}

		ttl := binary.BigEndian.Uint64(
			append([]byte{0, 0, 0, 0}, b...),
		)
		// skipping reserved(4 bytes) and timestamp(4 bytes) = 8
		_, err = byteReader(br, 8)
		if err != nil {
			values = append(
				values,
				fmt.Sprintf(
					"Invalid DNS record: %v",
					err,
				),
			)

			continue
		}
		// reading in Data(variable length, fun!)
		b, err = byteReader(br, int(datalength))
		if err != nil {
			values = append(
				values,
				fmt.Sprintf(
					"Invalid DNS record: %v",
					err,
				),
			)

			continue
		}

		switch recTypes[rectype] {
		case "A":
			data = net.IP(b).String()
		case "AAAA":
			data = net.IP(b).String()
		case "TXT", "HINFO", "ISDN", "X25", "LOC":
			data = string(b)
		case "CNAME",
			"NS",
			"PTR",
			"DNAME",
			"MB",
			"MG",
			"MR",
			"MD",
			"MF":
			data, err = dnsrpcnameToString(b)
			if err != nil {
				values = append(
					values,
					fmt.Sprintf(
						"Invalid DNS record: %v",
						err,
					),
				)

				continue
			}

		case "SRV":
			// Skipping priority and weight, 2 bytes each
			br2 := bytes.NewReader(b[4:])
			// read 2 bytes for port
			b, err = byteReader(br2, 2)
			if err != nil {
				values = append(
					values,
					fmt.Sprintf(
						"Invalid DNS record: %v",
						err,
					),
				)

				continue
			}

			port := binary.BigEndian.Uint16(b)
			b = make([]byte, br2.Len())

			_, err := br2.Read(b)
			if err != nil {
				values = append(
					values,
					fmt.Sprintf(
						"Invalid DNS record: %v",
						err,
					),
				)

				continue
			}

			data, err = dnsrpcnameToString(b)
			if err != nil {
				values = append(
					values,
					fmt.Sprintf(
						"Invalid DNS record: %v",
						err,
					),
				)

				continue
			}

			data = fmt.Sprintf("%s:%d", data, port)
		case "SOA":
			// Skipping serial, refresh, retry, expire, minimum (4 bytes each = 20 bytes )
			data, err = dnsrpcnameToString(b[20:])
			if err != nil {
				values = append(
					values,
					fmt.Sprintf(
						"Invalid DNS record: %v",
						err,
					),
				)

				continue
			}

		default:
			data = "Unsupported:" + hex.EncodeToString(b)
		}

		_ = ttl
		val := fmt.Sprintf(
			"%s(%s)",
			recTypes[rectype],
			data,
		)
		values = append(values, val)
	}
	return values
}

func msdsAllowedToActOnBehalfOfOtherIdentityTransform(bs [][]byte) []string {
	values := []string{}

	for _, b := range bs {
		sddl, err := sddlparse.SDDLFromBinary(b)
		if err != nil {
			values = append(values, err.Error())
			continue
		}

		value := ""

		var valueSb1136 strings.Builder
		for _, ace := range sddl.DACL {
			valueSb1136.WriteString(ace.String())
		}

		value += valueSb1136.String()

		values = append(
			values,
			reSDDL.ReplaceAllString(
				value+"\n    ",
				"\n      $1",
			),
		)
	}
	return values
}

func msdsGroupMSAMembershipTransform(bs [][]byte) []string {
	values := []string{}

	for _, b := range bs {
		sddl, err := sddlparse.SDDLFromBinary(b)
		if err != nil {
			values = append(values, err.Error())
			continue
		}
		value := ""
		var valueSb1159 strings.Builder
		for _, ace := range sddl.DACL {
			valueSb1159.WriteString(ace.String())
		}
		value += valueSb1159.String()
		values = append(
			values,
			reSDDL.ReplaceAllString(
				value+"\n    ",
				"\n      $1",
			),
		)
	}
	return values
}

func msdsManagedPasswordTransform(bs [][]byte) []string {
	values := []string{}

	for _, b := range bs {
		blob, err := ParseMSDSManagedPasswordBlob(b)
		if err != nil {
			values = append(
				values,
				fmt.Sprintf(
					"Error parsing blob: %v",
					err,
				),
			)

			continue
		}

		ntlmHash, err := blob.GetCurrentPasswordNTLMHash()
		if err != nil {
			values = append(
				values,
				fmt.Sprintf(
					"Error computing NTLM hash: %v",
					err,
				),
			)

			continue
		}

		values = append(
			values,
			"NTLM Hash: "+ntlmHash,
		)
	}
	return values
}

func ntSecurityDescriptorTransform(bs [][]byte) []string {
	values := []string{}

	for _, b := range bs {
		sddl, err := sddlparse.SDDLFromBinary(b)
		if err != nil {
			values = append(values, err.Error())
			continue
		}

		value := ""

		writemasks := sddlparse.ACCESS_MASK_GENERIC_ALL | sddlparse.ACCESS_MASK_GENERIC_WRITE | sddlparse.ACCESS_MASK_WRITE_OWNER | sddlparse.ACCESS_MASK_WRITE_DACL
		var valueSb1221 strings.Builder

		for _, ace := range sddl.DACL {
			if ace.AccessMask&writemasks > 0 {
				valueSb1221.WriteString(ace.String())
			}
		}

		value += valueSb1221.String()

		values = append(
			values,
			reSDDL.ReplaceAllString(
				value+"\n    ",
				"\n      $1",
			),
		)
	}
	return values
}

func objectGUIDTransform(bs [][]byte) []string {
	values := []string{}
	for _, b := range bs {
		values = append(values, decodeGUID(b))
	}
	return values
}

func objectSIDTransform(bs [][]byte) []string {
	values := []string{}
	for _, b := range bs {
		b, _ := decodeSID(b)
		values = append(values, b)
	}
	return values
}
