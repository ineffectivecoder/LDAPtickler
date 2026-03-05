package ldaptickler

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// This is our custom Result type
type Result struct {
	attrs map[string][]string
	bytes map[string][][]byte
	dn    string
}

// This parses the ldap.SearchResult.Entries
func NewResultFromLDAP(entry *ldap.Entry) *Result {
	var r Result

	r.dn = entry.DN

	r.attrs = map[string][]string{}
	r.bytes = map[string][][]byte{}
	for _, attr := range entry.Attributes {
		r.preprocess(attr)
	}

	return &r
}

// Adds all attributes except DN
func (r *Result) preprocess(attribute *ldap.EntryAttribute) {
	if strings.ToLower(attribute.Name) != "dn" {
		if transform, ok := transformsLookup[strings.ToLower(attribute.Name)]; ok {
			r.attrs[attribute.Name] = transform(attribute.ByteValues)
			r.attrs[attribute.Name+"_orig"] = attribute.Values
		} else {
			r.attrs[attribute.Name] = attribute.Values
			r.attrs[attribute.Name+"_orig"] = attribute.Values
		}
		r.bytes[attribute.Name] = attribute.ByteValues
	}
}

// Helper to return things
func (r *Result) GetAttr(attr string) []string {
	if _, ok := r.attrs[attr]; !ok {
		attr = strings.ToLower(attr)
	}
	return r.attrs[attr]
}

func (r *Result) GetAttrBytes(attr string) [][]byte {
	if _, ok := r.bytes[attr]; !ok {
		attr = strings.ToLower(attr)
	}
	return r.bytes[attr]
}

func (r *Result) GetFirstAttr(attr string) string {
	if len(r.GetAttr(attr)) == 0 {
		return ""
	}
	return r.GetAttr(attr)[0]
}

func (r *Result) GetFirstBytes(attr string) []byte {
	if len(r.GetAttrBytes(attr)) == 0 {
		return nil
	}
	return r.GetAttrBytes(attr)[0]
}

// Helper to return things
func (r *Result) GetAttrs() map[string][]string {
	return r.attrs
}

func (r *Result) GetBytes() map[string][][]byte {
	return r.bytes
}

// Helper to return things
func (r *Result) GetDN() string {
	return r.dn
}

func (r *Result) Length(attr string) int {
	return len(r.GetAttr(attr))
}

// This is for multiple Results
type Results []Result

func (rs *Results) Add(r Result) {
	(*rs) = append(*rs, r)
}

func (rs *Results) Length() int {
	return len(*rs)
}

func (rs *Results) Print() {
	for _, result := range *rs {
		fmt.Printf("  DN: %s\n", result.GetDN())

		keys := []string{}
		for key := range result.GetAttrs() {
			keys = append(keys, key)
		}

		slices.Sort(keys)

		for _, key := range keys {
			if strings.HasSuffix(key, "_orig") {
				continue
			}

			if result.Length(key) == 0 {
				fmt.Printf("    %s: No values found\n", key)
				continue
			}

			fmt.Printf("    %s: %v\n", key, result.GetAttr(key))
		}
	}
}
