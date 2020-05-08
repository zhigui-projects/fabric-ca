// Package revoke provides functionality for checking the validity of
// a cert. Specifically, the temporal validity of the certificate is
// checked first, then any CRL and OCSP url in the cert is checked.
package revoke

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/zhigui-projects/gmsm/sm2"
	"golang.org/x/crypto/ocsp"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	neturl "net/url"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	gmx509 "github.com/zhigui-projects/x509"
)

// HardFail determines whether the failure to check the revocation
// status of a certificate (i.e. due to network failure) causes
// verification to fail (a hard failure).
var HardFail = false

// CRLSet associates a PKIX certificate list with the URL the CRL is
// fetched from.
var CRLSet = map[string]*pkix.CertificateList{}
var crlLock = new(sync.Mutex)

// We can't handle LDAP certificates, so this checks to see if the
// URL string points to an LDAP resource so that we can ignore it.
func ldapURL(url string) bool {
	u, err := neturl.Parse(url)
	if err != nil {
		log.Warningf("error parsing url %s: %v", url, err)
		return false
	}
	if u.Scheme == "ldap" {
		return true
	}
	return false
}

// revCheck should check the certificate for any revocations. It
// returns a pair of booleans: the first indicates whether the certificate
// is revoked, the second indicates whether the revocations were
// successfully checked.. This leads to the following combinations:
//
//  false, false: an error was encountered while checking revocations.
//
//  false, true:  the certificate was checked successfully and
//                  it is not revoked.
//
//  true, true:   the certificate was checked successfully and
//                  it is revoked.
//
//  true, false:  failure to check revocation status causes
//                  verification to fail
func revCheck(cert *x509.Certificate) (revoked, ok bool) {
	for _, url := range cert.CRLDistributionPoints {
		if ldapURL(url) {
			log.Infof("skipping LDAP CRL: %s", url)
			continue
		}

		if revoked, ok := certIsRevokedCRL(cert, url); !ok {
			log.Warning("error checking revocation via CRL")
			if HardFail {
				return true, false
			}
			return false, false
		} else if revoked {
			log.Info("certificate is revoked via CRL")
			return true, true
		}
	}

	if revoked, ok := certIsRevokedOCSP(cert, HardFail); !ok {
		log.Warning("error checking revocation via OCSP")
		if HardFail {
			return true, false
		}
		return false, false
	} else if revoked {
		log.Info("certificate is revoked via OCSP")
		return true, true
	}

	return false, true
}

// fetchCRL fetches and parses a CRL.
func fetchCRL(url string) (*pkix.CertificateList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL")
	}

	body, err := crlRead(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return x509.ParseCRL(body)
}

func getIssuer(cert *x509.Certificate) *x509.Certificate {
	var issuer *x509.Certificate
	var err error
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchRemote(issuingCert)
		if err != nil {
			continue
		}
		break
	}

	return issuer

}

// check a cert against a specific CRL. Returns the same bool pair
// as revCheck.
func certIsRevokedCRL(cert *x509.Certificate, url string) (revoked, ok bool) {
	crl, ok := CRLSet[url]
	if ok && crl == nil {
		ok = false
		crlLock.Lock()
		delete(CRLSet, url)
		crlLock.Unlock()
	}

	var shouldFetchCRL = true
	if ok {
		if !crl.HasExpired(time.Now()) {
			shouldFetchCRL = false
		}
	}

	issuer := getIssuer(cert)

	if shouldFetchCRL {
		var err error
		crl, err = fetchCRL(url)
		if err != nil {
			log.Warningf("failed to fetch CRL: %v", err)
			return false, false
		}

		// check CRL signature

		if issuer != nil {
			_, isGM := issuer.PublicKey.(*sm2.PublicKey) ;
			if isGM {
				err = gmx509.CheckCRLSignature(issuer,crl)

			} else {
			    err = issuer.CheckCRLSignature(crl)
			}
			if err != nil {
				log.Warningf("failed to verify CRL: %v", err)
				return false, false
			}
		}

		crlLock.Lock()
		CRLSet[url] = crl
		crlLock.Unlock()
	}

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			log.Info("Serial number match: intermediate is revoked.")
			return true, true
		}
	}

	return false, true
}

// VerifyCertificate ensures that the certificate passed in hasn't
// expired and checks the CRL for the server.
func VerifyCertificate(cert *x509.Certificate) (revoked, ok bool) {
	if !time.Now().Before(cert.NotAfter) {
		log.Infof("Certificate expired %s\n", cert.NotAfter)
		return true, true
	} else if !time.Now().After(cert.NotBefore) {
		log.Infof("Certificate isn't valid until %s\n", cert.NotBefore)
		return true, true
	}

	return revCheck(cert)
}

func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	in, err := remoteRead(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	p, _ := pem.Decode(in)
	if p != nil {
		return helpers.ParseCertificatePEM(in)
	}
	cert, err := x509.ParseCertificate(in)
	if err !=nil{
		cert, err = gmx509.X509(gmx509.SM2).ParseCertificate(in)
	}
	return cert ,err
}

var ocspOpts = ocsp.RequestOptions{
	Hash: crypto.SHA1,
}

func certIsRevokedOCSP(leaf *x509.Certificate, strict bool) (revoked, ok bool) {
	var err error

	ocspURLs := leaf.OCSPServer
	if len(ocspURLs) == 0 {
		// OCSP not enabled for this certificate.
		return false, true
	}

	issuer := getIssuer(leaf)

	if issuer == nil {
		return false, false
	}

	ocspRequest, err := ocsp.CreateRequest(leaf, issuer, &ocspOpts)
	if err != nil {
		return
	}

	for _, server := range ocspURLs {
		resp, err := sendOCSPRequest(server, ocspRequest, leaf, issuer)
		if err != nil {
			if strict {
				return
			}
			continue
		}

		// There wasn't an error fetching the OCSP status.
		ok = true

		if resp.Status != ocsp.Good {
			// The certificate was revoked.
			revoked = true
		}

		return
	}
	return
}

// sendOCSPRequest attempts to request an OCSP response from the
// server. The error only indicates a failure to *fetch* the
// certificate, and *does not* mean the certificate is valid.
func sendOCSPRequest(server string, req []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	var resp *http.Response
	var err error
	if len(req) > 256 {
		buf := bytes.NewBuffer(req)
		resp, err = http.Post(server, "application/ocsp-request", buf)
	} else {
		reqURL := server + "/" + base64.StdEncoding.EncodeToString(req)
		resp, err = http.Get(reqURL)
	}

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve OSCP")
	}

	body, err := ocspRead(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	switch {
	case bytes.Equal(body, ocsp.UnauthorizedErrorResponse):
		return nil, errors.New("OSCP unauthorized")
	case bytes.Equal(body, ocsp.MalformedRequestErrorResponse):
		return nil, errors.New("OSCP malformed")
	case bytes.Equal(body, ocsp.InternalErrorErrorResponse):
		return nil, errors.New("OSCP internal error")
	case bytes.Equal(body, ocsp.TryLaterErrorResponse):
		return nil, errors.New("OSCP try later")
	case bytes.Equal(body, ocsp.SigRequredErrorResponse):
		return nil, errors.New("OSCP signature required")
	}
	_, isGM := issuer.PublicKey.(*sm2.PublicKey)
	if isGM{
		return ParseResponseForGMCert(body, leaf, issuer)
	} else {
	    return ocsp.ParseResponseForCert(body, leaf, issuer)
	}
}

var crlRead = ioutil.ReadAll

// SetCRLFetcher sets the function to use to read from the http response body
func SetCRLFetcher(fn func(io.Reader) ([]byte, error)) {
	crlRead = fn
}

var remoteRead = ioutil.ReadAll

// SetRemoteFetcher sets the function to use to read from the http response body
func SetRemoteFetcher(fn func(io.Reader) ([]byte, error)) {
	remoteRead = fn
}

var ocspRead = ioutil.ReadAll

// SetOCSPFetcher sets the function to use to read from the http response body
func SetOCSPFetcher(fn func(io.Reader) ([]byte, error)) {
	ocspRead = fn
}

///////////////////////////new add ///////////////
type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
}

type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}
var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
	crypto.Hash(gmx509.SM3):    asn1.ObjectIdentifier([]int{1, 2, 156, 10197, 1, 401, 1}),
}
var idPKIXOCSPBasic = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, oidSignatureMD2WithRSA, x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, oidSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
	{gmx509.SM2WithSM3, oidSignatureSM2WithSM3, x509.ECDSA, crypto.Hash(gmx509.SM3)},
}

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureSM2WithSM3      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidSignatureSM2WithSHA1     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
	oidSignatureSM2WithSHA256   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 503}
)
func getSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.oid) {
			return details.algo
		}
	}
	return x509.UnknownSignatureAlgorithm
}
func ParseResponseForGMCert(bytes []byte, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	var resp responseASN1
	rest, err := asn1.Unmarshal(bytes, &resp)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, ocsp.ParseError("trailing data in OCSP response")
	}

	if status := ocsp.ResponseStatus(resp.Status); status != ocsp.Success {
		return nil, ocsp.ResponseError{status}
	}

	if !resp.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		return nil, ocsp.ParseError("bad OCSP response type")
	}

	var basicResp basicResponse
	rest, err = asn1.Unmarshal(resp.Response.Response, &basicResp)
	if err != nil {
		return nil, err
	}

	if len(basicResp.Certificates) > 1 {
		return nil, ocsp.ParseError("OCSP response contains bad number of certificates")
	}

	if n := len(basicResp.TBSResponseData.Responses); n == 0 || cert == nil && n > 1 {
		return nil, ocsp.ParseError("OCSP response contains bad number of responses")
	}

	var singleResp singleResponse
	if cert == nil {
		singleResp = basicResp.TBSResponseData.Responses[0]
	} else {
		match := false
		for _, resp := range basicResp.TBSResponseData.Responses {
			if cert.SerialNumber.Cmp(resp.CertID.SerialNumber) == 0 {
				singleResp = resp
				match = true
				break
			}
		}
		if !match {
			return nil, ocsp.ParseError("no response matching the supplied certificate")
		}
	}

	ret := &ocsp.Response{
		TBSResponseData:    basicResp.TBSResponseData.Raw,
		Signature:          basicResp.Signature.RightAlign(),
		SignatureAlgorithm: getSignatureAlgorithmFromOID(basicResp.SignatureAlgorithm.Algorithm),
		Extensions:         singleResp.SingleExtensions,
		SerialNumber:       singleResp.CertID.SerialNumber,
		ProducedAt:         basicResp.TBSResponseData.ProducedAt,
		ThisUpdate:         singleResp.ThisUpdate,
		NextUpdate:         singleResp.NextUpdate,
	}

	// Handle the ResponderID CHOICE tag. ResponderID can be flattened into
	// TBSResponseData once https://go-review.googlesource.com/34503 has been
	// released.
	rawResponderID := basicResp.TBSResponseData.RawResponderID
	switch rawResponderID.Tag {
	case 1: // Name
		var rdn pkix.RDNSequence
		if rest, err := asn1.Unmarshal(rawResponderID.Bytes, &rdn); err != nil || len(rest) != 0 {
			return nil, ocsp.ParseError("invalid responder name")
		}
		ret.RawResponderName = rawResponderID.Bytes
	case 2: // KeyHash
		if rest, err := asn1.Unmarshal(rawResponderID.Bytes, &ret.ResponderKeyHash); err != nil || len(rest) != 0 {
			return nil, ocsp.ParseError("invalid responder key hash")
		}
	default:
		return nil, ocsp.ParseError("invalid responder id tag")
	}

	if len(basicResp.Certificates) > 0 {
		ret.Certificate, err = gmx509.X509(gmx509.SM2).ParseCertificate(basicResp.Certificates[0].FullBytes)
		if err != nil {
			return nil, err
		}

//		if err := ret.CheckSignatureFrom(ret.Certificate); err != nil {
		if err := CheckSignatureFrom(ret, ret.Certificate); err != nil {

			return nil, ocsp.ParseError("bad signature on embedded certificate: " + err.Error())
		}

		if issuer != nil {
			if err := gmx509.X509(gmx509.SM2).CheckCertSignature(issuer, ret.Certificate.SignatureAlgorithm, ret.Certificate.RawTBSCertificate, ret.Certificate.Signature); err != nil {
				return nil, ocsp.ParseError("bad OCSP signature: " + err.Error())
			}
		}
	} else if issuer != nil {
		if err := CheckSignatureFrom(ret, issuer); err != nil {
			return nil, ocsp.ParseError("bad OCSP signature: " + err.Error())
		}
	}

	for _, ext := range singleResp.SingleExtensions {
		if ext.Critical {
			return nil, ocsp.ParseError("unsupported critical extension")
		}
	}

	for h, oid := range hashOIDs {
		if singleResp.CertID.HashAlgorithm.Algorithm.Equal(oid) {
			ret.IssuerHash = h
			break
		}
	}
	if ret.IssuerHash == 0 {
		return nil, ocsp.ParseError("unsupported issuer hash algorithm")
	}

	switch {
	case bool(singleResp.Good):
		ret.Status = ocsp.Good
	case bool(singleResp.Unknown):
		ret.Status = ocsp.Unknown
	default:
		ret.Status = ocsp.Revoked
		ret.RevokedAt = singleResp.Revoked.RevocationTime
		ret.RevocationReason = int(singleResp.Revoked.Reason)
	}

	return ret, nil
}
func CheckSignatureFrom(resp *ocsp.Response, issuer *x509.Certificate) error {
	return  gmx509.X509(gmx509.SM2).CheckCertSignature(issuer,resp.SignatureAlgorithm, resp.TBSResponseData, resp.Signature)
}
