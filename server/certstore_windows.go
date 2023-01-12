// Copyright 2019-2022 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Adapted, updated, and enhanced from CertToStore, https://github.com/google/certtostore/releases/tag/v1.0.2
// Apache License, Version 2.0, Copyright 2017 Google Inc.

//go:build windows

package server

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/sys/windows"
	"io"
	"math/big"
	"reflect"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	// wincrypt.h constants
	winAcquireCached           = 0x1                                                   // CRYPT_ACQUIRE_CACHE_FLAG
	winAcquireSilent           = 0x40                                                  // CRYPT_ACQUIRE_SILENT_FLAG
	winAcquireOnlyNCryptKey    = 0x40000                                               // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
	winEncodingX509ASN         = 1                                                     // X509_ASN_ENCODING
	winEncodingPKCS7           = 65536                                                 // PKCS_7_ASN_ENCODING
	winCertStoreProvSystem     = 10                                                    // CERT_STORE_PROV_SYSTEM
	winCertStoreCurrentUser    = uint32(winCertStoreCurrentUserID << winCompareShift)  // CERT_SYSTEM_STORE_CURRENT_USER
	winCertStoreLocalMachine   = uint32(winCertStoreLocalMachineID << winCompareShift) // CERT_SYSTEM_STORE_LOCAL_MACHINE
	winCertStoreCurrentUserID  = 1                                                     // CERT_SYSTEM_STORE_CURRENT_USER_ID
	winCertStoreLocalMachineID = 2                                                     // CERT_SYSTEM_STORE_LOCAL_MACHINE_ID
	winInfoIssuerFlag          = 4                                                     // CERT_INFO_ISSUER_FLAG
	winInfoSubjectFlag         = 7                                                     // CERT_INFO_SUBJECT_FLAG
	winCompareNameStrW         = 8                                                     // CERT_COMPARE_NAME_STR_A
	winCompareShift            = 16                                                    // CERT_COMPARE_SHIFT

	// Reference https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
	winFindIssuerStr  = winCompareNameStrW<<winCompareShift | winInfoIssuerFlag  // CERT_FIND_ISSUER_STR_W
	winFindSubjectStr = winCompareNameStrW<<winCompareShift | winInfoSubjectFlag // CERT_FIND_SUBJECT_STR_W

	winNcryptKeySpec = 0xFFFFFFFF // CERT_NCRYPT_KEY_SPEC

	winBCryptPadPSS     uintptr = 0x8 // Modern TLS 1.2+
	winBCryptPadPSSSalt uint32  = 32  // default 20, 32 optimal for typical SHA256 hash

	winRSA1Magic = 0x31415352 // "RSA1" BCRYPT_RSAPUBLIC_MAGIC

	winECS1Magic = 0x31534345 // "ECS1" BCRYPT_ECDSA_PUBLIC_P256_MAGIC
	winECS3Magic = 0x33534345 // "ECS3" BCRYPT_ECDSA_PUBLIC_P384_MAGIC
	winECS5Magic = 0x35534345 // "ECS5" BCRYPT_ECDSA_PUBLIC_P521_MAGIC

	winECK1Magic = 0x314B4345 // "ECK1" BCRYPT_ECDH_PUBLIC_P256_MAGIC
	winECK3Magic = 0x334B4345 // "ECK3" BCRYPT_ECDH_PUBLIC_P384_MAGIC
	winECK5Magic = 0x354B4345 // "ECK5" BCRYPT_ECDH_PUBLIC_P521_MAGIC

	winCryptENotFound = 0x80092004 // CRYPT_E_NOT_FOUND

	providerMSSoftware = "Microsoft Software Key Storage Provider"
)

var (
	winBCryptRSAPublicBlob = winWide("RSAPUBLICBLOB")
	winBCryptECCPublicBlob = winWide("ECCPUBLICBLOB")

	winNCryptAlgorithmGroupProperty = winWide("Algorithm Group") // NCRYPT_ALGORITHM_GROUP_PROPERTY
	winNCryptUniqueNameProperty     = winWide("Unique Name")     // NCRYPT_UNIQUE_NAME_PROPERTY
	winNCryptECCCurveNameProperty   = winWide("ECCCurveName")    // NCRYPT_ECC_CURVE_NAME_PROPERTY
	winNCryptProviderHandleProperty = winWide("Provider Handle") // NCRYPT_PROV_HANDLE

	winCurveIDs = map[uint32]elliptic.Curve{
		winECS1Magic: elliptic.P256(), // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
		winECS3Magic: elliptic.P384(), // BCRYPT_ECDSA_PUBLIC_P384_MAGIC
		winECS5Magic: elliptic.P521(), // BCRYPT_ECDSA_PUBLIC_P521_MAGIC
		winECK1Magic: elliptic.P256(), // BCRYPT_ECDH_PUBLIC_P256_MAGIC
		winECK3Magic: elliptic.P384(), // BCRYPT_ECDH_PUBLIC_P384_MAGIC
		winECK5Magic: elliptic.P521(), // BCRYPT_ECDH_PUBLIC_P521_MAGIC
	}

	winCurveNames = map[string]elliptic.Curve{
		"nistP256": elliptic.P256(), // BCRYPT_ECC_CURVE_NISTP256
		"nistP384": elliptic.P384(), // BCRYPT_ECC_CURVE_NISTP384
		"nistP521": elliptic.P521(), // BCRYPT_ECC_CURVE_NISTP521
	}

	winAlgIDs = map[crypto.Hash]*uint16{
		crypto.SHA1:   winWide("SHA1"),   // BCRYPT_SHA1_ALGORITHM
		crypto.SHA256: winWide("SHA256"), // BCRYPT_SHA256_ALGORITHM
		crypto.SHA384: winWide("SHA384"), // BCRYPT_SHA384_ALGORITHM
		crypto.SHA512: winWide("SHA512"), // BCRYPT_SHA512_ALGORITHM
	}

	// MY is well-known system store on Windows that holds personal certificates
	winMyStore = winWide("MY")

	// These DLLs must be available on all Windows hosts
	winCrypt32 = windows.MustLoadDLL("crypt32.dll")
	winNCrypt  = windows.MustLoadDLL("ncrypt.dll")

	winCertFindCertificateInStore        = winCrypt32.MustFindProc("CertFindCertificateInStore")
	winCryptAcquireCertificatePrivateKey = winCrypt32.MustFindProc("CryptAcquireCertificatePrivateKey")
	winNCryptExportKey                   = winNCrypt.MustFindProc("NCryptExportKey")
	winNCryptFreeObject                  = winNCrypt.MustFindProc("NCryptFreeObject")
	winNCryptOpenStorageProvider         = winNCrypt.MustFindProc("NCryptOpenStorageProvider")
	winNCryptGetProperty                 = winNCrypt.MustFindProc("NCryptGetProperty")
	winNCryptSignHash                    = winNCrypt.MustFindProc("NCryptSignHash")

	winFnGetProperty = winGetProperty
)

type winPSSPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   uint32
}

// CertStoreTLSConfig fulfills the same function as reading cert and key pair from pem files but
// sources the Windows certificate store instead
func CertStoreTLSConfig(tc *TLSConfigOpts, config *tls.Config) error {
	var (
		leaf     *x509.Certificate
		leafCtx  *windows.CertContext
		pk       *winKey
		vOpts    = x509.VerifyOptions{}
		chains   [][]*x509.Certificate
		chain    []*x509.Certificate
		rawChain [][]byte
	)

	// By CertStoreType, open a CertStore
	if tc.CertStore == WindowsCurrentUser || tc.CertStore == WindowsLocalMachine {
		var scope uint32
		cs, err := winOpenCertStore(providerMSSoftware)
		if err != nil || cs == nil {
			return err
		}
		if tc.CertStore == WindowsCurrentUser {
			scope = winCertStoreCurrentUser
		}
		if tc.CertStore == WindowsLocalMachine {
			scope = winCertStoreLocalMachine
		}

		// certByIssuer or certBySubject
		if tc.CertMatchBy == MatchBySubject || tc.CertMatchBy == _CERTMATCHBYEMPTY_ {
			leaf, leafCtx, err = cs.certBySubject(tc.CertMatch, scope)
		} else if tc.CertMatchBy == MatchByIssuer {
			leaf, leafCtx, err = cs.certByIssuer(tc.CertMatch, scope)
		} else {
			return fmt.Errorf("cert match by type not implemented")
		}
		if err != nil {
			return err
		}
		if leaf == nil || leafCtx == nil {
			return fmt.Errorf("no cert match in cert store")
		}
		pk, err = cs.certKey(leafCtx)
		if err != nil {
			return err
		}
		if pk == nil {
			return fmt.Errorf("no private key found in cert")
		}
	} else {
		return fmt.Errorf("cert store type not implemented")
	}

	// Get intermediates in the cert store for the found leaf IFF there is a full chain of trust in the store
	// otherwise just use leaf as the final chain.
	//
	// Using std lib Verify as a reliable way to get valid chains out of the win store for the leaf; however,
	// using empty options since server TLS stanza could be TLS role as server identity or client identity.
	chains, err := leaf.Verify(vOpts)
	if err != nil || len(chains) == 0 {
		chains = append(chains, []*x509.Certificate{leaf})
	}

	// We have at least one verified chain so pop the first chain and remove the self-signed CA cert (if present)
	// from the end of the chain
	chain = chains[0]
	if len(chain) > 1 {
		chain = chain[:len(chain)-1]
	}

	// For tls.Certificate.Certificate need a [][]byte from []*x509.Certificate
	// Approximate capacity for efficiency
	rawChain = make([][]byte, 0, len(chain))
	for _, link := range chain {
		rawChain = append(rawChain, link.Raw)
	}

	tlsCert := tls.Certificate{
		Certificate: rawChain,
		PrivateKey:  pk,
		Leaf:        leaf,
	}
	config.Certificates = []tls.Certificate{tlsCert}

	// note: pk is a windows pointer (not freed by Go) but needs to live the life of the server for Signing.
	// The cert context (leafCtx) windows pointer must not be freed underneath the pk so also life of the server.
	return nil
}

// winWide returns a pointer to uint16 representing the equivalent
// to a Windows LPCWSTR.
func winWide(s string) *uint16 {
	w := utf16.Encode([]rune(s))
	w = append(w, 0)
	return &w[0]
}

// winOpenProvider gets a provider handle for subsequent calls
func winOpenProvider(provider string) (uintptr, error) {
	var hProv uintptr
	pname := winWide(provider)
	// Open the provider, the last parameter is not used
	r, _, err := winNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&hProv)), uintptr(unsafe.Pointer(pname)), 0)
	if r == 0 {
		return hProv, nil
	}
	return hProv, fmt.Errorf("NCryptOpenStorageProvider returned %X: %v", r, err)
}

// winFindCert wraps the CertFindCertificateInStore library call. Note that any cert context passed
// into prev will be freed. If no certificate was found, nil will be returned.
func winFindCert(store windows.Handle, enc, findFlags, findType uint32, para *uint16, prev *windows.CertContext) (*windows.CertContext, error) {
	h, _, err := winCertFindCertificateInStore.Call(
		uintptr(store),
		uintptr(enc),
		uintptr(findFlags),
		uintptr(findType),
		uintptr(unsafe.Pointer(para)),
		uintptr(unsafe.Pointer(prev)),
	)
	if h == 0 {
		// Actual error, or simply not found?
		if errno, ok := err.(syscall.Errno); ok && errno == winCryptENotFound {
			return nil, nil
		}
		return nil, err
	}
	return (*windows.CertContext)(unsafe.Pointer(h)), nil
}

// winCertStore is a CertStore implementation for the Windows Certificate Store.
type winCertStore struct {
	Prov     uintptr
	ProvName string
	stores   map[string]*winStoreHandle
	mu       sync.Mutex
}

// winOpenCertStore creates a winCertStore. Call Close() when finished using the store.
func winOpenCertStore(provider string) (*winCertStore, error) {
	cngProv, err := winOpenProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("unable to open crypto provider or provider not available: %v", err)
	}

	wcs := &winCertStore{
		Prov:     cngProv,
		ProvName: provider,
		stores:   make(map[string]*winStoreHandle),
	}

	return wcs, nil
}

// winCertContextToX509 creates an x509.Certificate from a Windows cert context.
func winCertContextToX509(ctx *windows.CertContext) (*x509.Certificate, error) {
	var der []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&der))
	slice.Data = uintptr(unsafe.Pointer(ctx.EncodedCert))
	slice.Len = int(ctx.Length)
	slice.Cap = int(ctx.Length)
	return x509.ParseCertificate(der)
}

// certByIssuer matches and returns the first certificate found by passed issuer.
// CertContext pointer returned allows subsequent key operations like Sign. Caller specifies
// current user's personal certs or local machine's personal certs using storeType.
// See CERT_FIND_ISSUER_STR description at https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
func (w *winCertStore) certByIssuer(issuer string, storeType uint32) (*x509.Certificate, *windows.CertContext, error) {
	return w.certSearch(winFindIssuerStr, issuer, winMyStore, storeType)
}

// certBySubject matches and returns the first certificate found by passed subject field.
// CertContext pointer returned allows subsequent key operations like Sign. Caller specifies
// current user's personal certs or local machine's personal certs using storeType.
// See CERT_FIND_SUBJECT_STR description at https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
func (w *winCertStore) certBySubject(subject string, storeType uint32) (*x509.Certificate, *windows.CertContext, error) {
	return w.certSearch(winFindSubjectStr, subject, winMyStore, storeType)
}

// certSearch is a helper function to lookup certificates based on search type and match value.
// store is used to specify which store to perform the lookup in (system or user).
func (w *winCertStore) certSearch(searchType uint32, matchValue string, searchRoot *uint16, store uint32) (*x509.Certificate, *windows.CertContext, error) {
	h, err := w.storeHandle(store, searchRoot)
	if err != nil {
		return nil, nil, err
	}

	var prev *windows.CertContext
	var cert *x509.Certificate

	i, err := windows.UTF16PtrFromString(matchValue)
	if err != nil {
		return nil, nil, err
	}

	// pass 0 as the third parameter because it is not used
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa376064(v=vs.85).aspx
	nc, err := winFindCert(h, winEncodingX509ASN|winEncodingPKCS7, 0, searchType, i, prev)
	if err != nil {
		return nil, nil, fmt.Errorf("error acquiring cert from store: %v", err)
	}
	if nc != nil {
		// certificate found
		prev = nc

		// Extract the DER-encoded certificate from the cert context.
		xc, err := winCertContextToX509(nc)
		if err == nil {
			cert = xc
		} else {
			return nil, nil, fmt.Errorf("unable to extract x509 from cert: [%s]", err.Error())
		}
	} else {
		return nil, nil, fmt.Errorf("could not find cert in store")
	}

	if cert == nil {
		return nil, nil, fmt.Errorf("unknown error extracting x509 from cert")
	}

	return cert, prev, nil
}

func winFreeObject(h uintptr) error {
	r, _, err := winNCryptFreeObject.Call(h)
	if r == 0 {
		return nil
	}
	return fmt.Errorf("NCryptFreeObject returned %X: %v", r, err)
}

type winStoreHandle struct {
	handle *windows.Handle
}

func winNewStoreHandle(provider uint32, store *uint16) (*winStoreHandle, error) {
	var s winStoreHandle
	if s.handle != nil {
		return &s, nil
	}
	st, err := windows.CertOpenStore(
		winCertStoreProvSystem,
		0,
		0,
		provider,
		uintptr(unsafe.Pointer(store)))
	if err != nil {
		return nil, fmt.Errorf("CertOpenStore for the user store returned: %v", err)
	}
	s.handle = &st
	return &s, nil
}

// winKey implements crypto.Signer and crypto.Decrypter for key based operations.
type winKey struct {
	handle         uintptr
	pub            crypto.PublicKey
	Container      string
	AlgorithmGroup string
}

// Public exports a public key to implement crypto.Signer
func (k winKey) Public() crypto.PublicKey {
	return k.pub
}

// Sign returns the signature of a hash to implement crypto.Signer
func (k winKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch k.AlgorithmGroup {
	case "ECDSA", "ECDH":
		return winSignECDSA(k.handle, digest)
	case "RSA":
		hf := opts.HashFunc()
		algID, ok := winAlgIDs[hf]
		if !ok {
			return nil, fmt.Errorf("unsupported RSA hash algorithm %v", hf)
		}
		return winSignRSA(k.handle, digest, algID)
	default:
		return nil, fmt.Errorf("unsupported algorithm group %v", k.AlgorithmGroup)
	}
}

func winSignECDSA(kh uintptr, digest []byte) ([]byte, error) {
	var size uint32
	// Obtain the size of the signature
	r, _, err := winNCryptSignHash.Call(
		kh,
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during size check: %v", r, err)
	}

	// Obtain the signature data
	buf := make([]byte, size)
	r, _, err = winNCryptSignHash.Call(
		kh,
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during signing: %v", r, err)
	}
	if len(buf) != int(size) {
		return nil, errors.New("invalid length")
	}

	return winPackECDSASigValue(bytes.NewReader(buf[:size]), len(digest))
}

func winPackECDSASigValue(r io.Reader, digestLength int) ([]byte, error) {
	sigR := make([]byte, digestLength)
	if _, err := io.ReadFull(r, sigR); err != nil {
		return nil, fmt.Errorf("failed to read R: %v", err)
	}

	sigS := make([]byte, digestLength)
	if _, err := io.ReadFull(r, sigS); err != nil {
		return nil, fmt.Errorf("failed to read S: %v", err)
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(sigR))
		b.AddASN1BigInt(new(big.Int).SetBytes(sigS))
	})
	return b.Bytes()
}

func winSignRSA(kh uintptr, digest []byte, algID *uint16) ([]byte, error) {
	// PSS padding for TLS 1.2+
	padInfo := winPSSPaddingInfo{pszAlgID: algID, cbSalt: winBCryptPadPSSSalt}

	var size uint32
	// Obtain the size of the signature
	r, _, err := winNCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		winBCryptPadPSS)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during size check: %v", r, err)
	}

	// Obtain the signature data
	sig := make([]byte, size)
	r, _, err = winNCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		winBCryptPadPSS)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during signing: %v", r, err)
	}

	return sig[:size], nil
}

// certKey wraps CryptAcquireCertificatePrivateKey. It obtains the CNG private
// key of a known certificate and returns a pointer to a winKey which implements
// both crypto.Signer. When a nil cert context is passed
// a nil key is intentionally returned, to model the expected behavior of a
// non-existent cert having no private key.
// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
func (w *winCertStore) certKey(cert *windows.CertContext) (*winKey, error) {
	// Return early if a nil cert was passed.
	if cert == nil {
		return nil, nil
	}
	var (
		kh       uintptr
		spec     uint32
		mustFree int
	)
	r, _, err := winCryptAcquireCertificatePrivateKey.Call(
		uintptr(unsafe.Pointer(cert)),
		winAcquireCached|winAcquireSilent|winAcquireOnlyNCryptKey,
		0, // Reserved, must be null.
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(&spec)),
		uintptr(unsafe.Pointer(&mustFree)),
	)
	// If the function succeeds, the return value is nonzero (TRUE).
	if r == 0 {
		return nil, fmt.Errorf("winCryptAcquireCertificatePrivateKey returned %X: %v", r, err)
	}
	if mustFree != 0 {
		return nil, fmt.Errorf("wrong mustFree [%d != 0]", mustFree)
	}
	if spec != winNcryptKeySpec {
		return nil, fmt.Errorf("wrong keySpec [%d != %d]", spec, winNcryptKeySpec)
	}

	return winKeyMetadata(kh)
}

func winKeyMetadata(kh uintptr) (*winKey, error) {
	// uc is used to populate the unique container name attribute of the private key
	uc, err := winGetPropertyStr(kh, winNCryptUniqueNameProperty)
	if err != nil {
		return nil, fmt.Errorf("unable to determine key unique name: %v", err)
	}

	// get the provider handle
	ph, err := winGetPropertyHandle(kh, winNCryptProviderHandleProperty)
	if err != nil {
		return nil, fmt.Errorf("unable to determine key provider: %v", err)
	}
	defer func(h uintptr) {
		_ = winFreeObject(h)
	}(ph)

	alg, err := winGetPropertyStr(kh, winNCryptAlgorithmGroupProperty)
	if err != nil {
		return nil, fmt.Errorf("unable to determine key algorithm: %v", err)
	}

	var pub crypto.PublicKey

	switch alg {
	case "ECDSA", "ECDH":
		buf, err := winExport(kh, winBCryptECCPublicBlob)
		if err != nil {
			return nil, fmt.Errorf("failed to export ECC public key: %v", err)
		}
		pub, err = unmarshalECC(buf, kh)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ECC public key: %v", err)
		}
	case "RSA":
		buf, err := winExport(kh, winBCryptRSAPublicBlob)
		if err != nil {
			return nil, fmt.Errorf("failed to winExport %v public key: %v", alg, err)
		}
		pub, err = winUnmarshalRSA(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal %v public key: %v", alg, err)
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm %v", alg)
	}

	return &winKey{handle: kh, pub: pub, Container: uc, AlgorithmGroup: alg}, nil
}

func winGetProperty(kh uintptr, property *uint16) ([]byte, error) {
	var strSize uint32
	r, _, err := winNCryptGetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(property)),
		0,
		0,
		uintptr(unsafe.Pointer(&strSize)),
		0,
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptGetProperty(%v) returned %X during size check: %v", property, r, err)
	}

	buf := make([]byte, strSize)
	r, _, err = winNCryptGetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(property)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(strSize),
		uintptr(unsafe.Pointer(&strSize)),
		0,
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptGetProperty %v returned %X during winExport: %v", property, r, err)
	}

	return buf, nil
}

func winGetPropertyHandle(kh uintptr, property *uint16) (uintptr, error) {
	buf, err := winGetProperty(kh, property)
	if err != nil {
		return 0, err
	}
	if len(buf) < 1 {
		return 0, fmt.Errorf("empty result")
	}
	return **(**uintptr)(unsafe.Pointer(&buf)), nil
}

func winGetPropertyStr(kh uintptr, property *uint16) (string, error) {
	buf, err := winFnGetProperty(kh, property)
	if err != nil {
		return "", err
	}
	uc := bytes.ReplaceAll(buf, []byte{0x00}, []byte(""))
	return string(uc), nil
}

func winExport(kh uintptr, blobType *uint16) ([]byte, error) {
	var size uint32
	// When obtaining the size of a public key, most parameters are not required
	r, _, err := winNCryptExportKey.Call(
		kh,
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey returned %X during size check: %v", r, err)
	}

	// Place the exported key in buf now that we know the size required
	buf := make([]byte, size)
	r, _, err = winNCryptExportKey.Call(
		kh,
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey returned %X during winExport: %v", r, err)
	}
	return buf, nil
}

func unmarshalECC(buf []byte, kh uintptr) (*ecdsa.PublicKey, error) {
	// BCRYPT_ECCKEY_BLOB from bcrypt.h
	header := struct {
		Magic uint32
		Key   uint32
	}{}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	curve, ok := winCurveIDs[header.Magic]
	if !ok {
		// Fix for b/185945636, where despite specifying the curve, nCrypt returns
		// an incorrect response with BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC.
		var err error
		curve, err = winCurveName(kh)
		if err != nil {
			return nil, fmt.Errorf("unsupported header magic: %x and cannot match the curve by name: %v", header.Magic, err)
		}
	}

	keyX := make([]byte, header.Key)
	if n, err := r.Read(keyX); n != int(header.Key) || err != nil {
		return nil, fmt.Errorf("failed to read key X (%d, %v)", n, err)
	}

	keyY := make([]byte, header.Key)
	if n, err := r.Read(keyY); n != int(header.Key) || err != nil {
		return nil, fmt.Errorf("failed to read key Y (%d, %v)", n, err)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(keyX),
		Y:     new(big.Int).SetBytes(keyY),
	}
	return pub, nil
}

// winCurveName reads the curve name property and returns the corresponding curve.
func winCurveName(kh uintptr) (elliptic.Curve, error) {
	cn, err := winGetPropertyStr(kh, winNCryptECCCurveNameProperty)
	if err != nil {
		return nil, fmt.Errorf("unable to determine the curve property name: %v", err)
	}
	curve, ok := winCurveNames[cn]
	if !ok {
		return nil, fmt.Errorf("unknown curve name")
	}
	return curve, nil
}

func winUnmarshalRSA(buf []byte) (*rsa.PublicKey, error) {
	// BCRYPT_RSA_BLOB from bcrypt.h
	header := struct {
		Magic         uint32
		BitLength     uint32
		PublicExpSize uint32
		ModulusSize   uint32
		UnusedPrime1  uint32
		UnusedPrime2  uint32
	}{}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	if header.Magic != winRSA1Magic {
		return nil, fmt.Errorf("invalid header magic %x", header.Magic)
	}

	if header.PublicExpSize > 8 {
		return nil, fmt.Errorf("unsupported public exponent size (%d bits)", header.PublicExpSize*8)
	}

	exp := make([]byte, 8)
	if n, err := r.Read(exp[8-header.PublicExpSize:]); n != int(header.PublicExpSize) || err != nil {
		return nil, fmt.Errorf("failed to read public exponent (%d, %v)", n, err)
	}

	mod := make([]byte, header.ModulusSize)
	if n, err := r.Read(mod); n != int(header.ModulusSize) || err != nil {
		return nil, fmt.Errorf("failed to read modulus (%d, %v)", n, err)
	}

	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(mod),
		E: int(binary.BigEndian.Uint64(exp)),
	}
	return pub, nil
}

// storeHandle returns a handle to a given cert store, opening the handle as needed.
func (w *winCertStore) storeHandle(provider uint32, store *uint16) (windows.Handle, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := fmt.Sprintf("%d%s", provider, windows.UTF16PtrToString(store))
	var err error
	if w.stores[key] == nil {
		w.stores[key], err = winNewStoreHandle(provider, store)
		if err != nil {
			return 0, err
		}
	}
	return *w.stores[key].handle, nil
}

// Verify interface conformance.
var _ CertStore = &winCertStore{}
var _ Credential = &winKey{}
