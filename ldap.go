package main

import (
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	LDAP_PORT           uint64 = 389
	LDAP_AUTH_OTHERKIND uint64 = 0x86
	LDAP_AUTH_NEGOTIATE uint64 = (LDAP_AUTH_OTHERKIND | 0x0400)
	LDAP_SUCCESS        uint64 = 0
	LDAP_SCOPE_BASE     uint64 = 0x00
	LDAP_SCOPE_ONELEVEL uint64 = 0x01
	LDAP_SCOPE_SUBTREE  uint64 = 0x02
)

func ldapGetValues(ld uintptr, entry uintptr, attr string) []string {
	attrPtr, _ := syscall.BytePtrFromString(attr)
	vals := ldap_get_valuesA(ld, entry, attrPtr)
	numValues := ldap_count_valuesA(vals)
	log.Printf("numValues: %d\n", numValues)
	var resStrings []string
	for i := 0; i < int(numValues); i++ {
		val := (**uint8)(unsafe.Add(unsafe.Pointer(vals), i*8))
		resStrings = append(resStrings, windows.BytePtrToString(*val))
	}
	ldap_value_free(vals)
	return resStrings
}

func (ldap LdapServer) ldapGetBase() string {
	ld, _ := ldap_initW(ldap.host, ldap.port)
	var res uintptr
	var numEntries uint64

	iRtn := ldap_bind_sW(ld, nil, nil, LDAP_AUTH_NEGOTIATE)
	if iRtn != LDAP_SUCCESS {
		log.Fatalln("Bind error")
	} else {
		log.Println("Bind success")
	}

	ldapStatus := ldap_search_sA(ld, nil, LDAP_SCOPE_BASE, nil, nil, 0, &res)
	if ldapStatus != LDAP_SUCCESS {
		log.Fatalln("ldap_search_sA error")
	}

	numEntries = ldap_count_entries(ld, res)
	log.Printf("entries found(Base value): %d\n", numEntries)

	domainDN := ldapGetValues(ld, res, "defaultNamingContext")[0]

	ldap_unbind_s(ld)

	return domainDN
}

func (ldap LdapServer) ldapSearch(baseStr string, filterStr string) [](map[string][]string) {
	ld, _ := ldap_initW(ldap.host, ldap.port)
	var res uintptr
	var ber uintptr
	var numEntries uint64

	iRtn := ldap_bind_sW(ld, nil, nil, LDAP_AUTH_NEGOTIATE)
	if iRtn != LDAP_SUCCESS {
		log.Fatalln("Bind error")
	} else {
		log.Println("Bind success")
	}

	base, err := syscall.BytePtrFromString(baseStr)
	if err != nil {
		panic(err)
	}

	filter, err := syscall.BytePtrFromString(filterStr)
	if err != nil {
		panic(err)
	}

	ldapStatus := ldap_search_sA(ld, base, LDAP_SCOPE_SUBTREE, filter, nil, 0, &res)
	if ldapStatus != LDAP_SUCCESS {
		log.Fatalln("ldap_search_sA error")
	}

	numEntries = ldap_count_entries(ld, res)
	log.Printf("entries found(filter): %d\n", numEntries)

	entry := ldap_first_entry(ld, res)

	ldapResults := [](map[string][]string){}

	for i := 0; i < int(numEntries); i++ {
		attr := ldap_first_attribute(ld, entry, &ber)
		attrs := map[string][]string{}
		for {
			if attr == nil {
				break
			}
			attrStr := windows.BytePtrToString(attr)
			attrVals := ldapGetValues(ld, entry, attrStr)
			for _, val := range attrVals {
				log.Printf("%s: %s\n", attrStr, val)
			}
			attrs[attrStr] = attrVals
			attr = ldap_next_attribute(ld, entry, ber)
		}
		ldapResults = append(ldapResults, attrs)
		ldap_memfree(attr)
		entry = ldap_next_entry(ld, entry)
	}

	ldap_unbind_s(ld)
	return ldapResults
}
