package pdf_sign

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"log"
	"time"

	"github.com/philhug/go-trustlists/pkg/trustlists"
	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// Struct for unmarshal of signed attribute RevocationInfoArchival
type revocationInfoArchival struct {
	CRL          []asn1.RawValue `asn1:"tag:0,optional"`
	OCSP         []asn1.RawValue `asn1:"tag:1,optional"`
	OtherRevInfo []asn1.RawValue `asn1:"tag:2,optional"`
}

// IsTimestampOnly returns true if the signature is a timestamp (instead of a CMS signature)
func IsTimestampOnly(signature *pkcs7.PKCS7) (bool, error) {

	signers := signature.Signers
	if len(signers) != 1 {
		return false, errors.New("only 1 signer allowed")
	}
	signer := signers[0]

	// SigningTime should be 1.2.840.113549.1.9.5 and be part of the authenticated attributes
	var OIDAttributeSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	for _, authattr := range signer.AuthenticatedAttributes {

		// If found, we asume this is a timestamp
		if authattr.Type.Equal(OIDAttributeSigningTime) {
			return true, nil
		}
	}
	// Signing time not found, so it's not a CAdES signature (so it can't be a timestamp)
	return false, nil

}

// ExtractSigningTime extracts the signingTime from a timestamp
func ExtractSigningTime(timestamp *pkcs7.PKCS7) (time.Time, error) {

	var signingTime time.Time

	signers := timestamp.Signers
	if len(signers) != 1 {
		return signingTime, errors.New("the number of signers must be exactly 1")
	}

	signer := signers[0]

	// SigningTime is 1.2.840.113549.1.9.5
	// It should be part of the authenticated attributes for a CAdES signature
	var OIDAttributeSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	for _, authattr := range signer.AuthenticatedAttributes {

		if authattr.Type.Equal(OIDAttributeSigningTime) {
			signingTimeBytes := authattr.Value.Bytes
			asn1.Unmarshal(signingTimeBytes, &signingTime)
		}
	}

	return signingTime, nil
}

// ExtractTimestamp extracts the timestamp from a signature
func ExtractTimestamp(signature *pkcs7.PKCS7) (*pkcs7.PKCS7, error) {

	var timestamp *pkcs7.PKCS7

	signers := signature.Signers

	// Only 1 signer allowed
	if len(signers) != 1 {
		return timestamp, errors.New("there must be only one signer on the pkcs7")
	}

	signerInfo := signers[0]

	// The timestamp is included in the "SignerInfo" as an unauthenticated attribute
	// The timestamp is a CADES signature of the "authenticated attributes"
	unauthAttrs := signerInfo.UnauthenticatedAttributes
	for _, unauthAttr := range unauthAttrs {

		// LATER DEBUG info
		//log.Printf("%d unauthenticated attribute type %s found in timestamp\n", i, unauthAttr.Type)

		// Timestamp should be 1.2.840.113549.1.9.16.2.14 according to RFC3161 (Appendix A)
		if unauthAttr.Type.String() == "1.2.840.113549.1.9.16.2.14" {

			// The signingTime must be the one corresponding to the AuthAttribute of the timestamp
			// The timestamp is a CADES signature
			timestamp, err := pkcs7.Parse(unauthAttr.Value.Bytes)
			if err != nil {
				return timestamp, err
			}
			return timestamp, nil
		}
	}
	return timestamp, errors.New("no timestamp found in pkcs7")
}

// ExtractAndVerifyTimestamp extracts the timestamp and its signingTime and verifies the timestamp signature
func ExtractAndVerifyTimestamp(signature *pkcs7.PKCS7, trustedAnchors *x509.CertPool) (time.Time, *pkcs7.PKCS7, error) {

	var signingTime time.Time

	// Extract timestamp from pkcs7
	timestamp, err := ExtractTimestamp(signature)
	if err != nil {
		return signingTime, timestamp, err
	}
	log.Printf("timestamp extracted from pkcs7")

	// Extract signing time from timestamp
	signingTime, err = ExtractSigningTime(timestamp)
	if err != nil {
		return signingTime, timestamp, err
	}
	log.Println("signed signing time in timestamp:", signingTime)

	// Verify timestamp signature
	// TODO content? Where does timestamp.Content come from?
	_, err = VerifyPkcs7(timestamp, signingTime, timestamp.Content, trustedAnchors)
	if err != nil {
		return signingTime, timestamp, err
	}
	log.Println("timestamp verified successfully")
	log.Println("timestamp signature algorithm: ", timestamp.GetOnlySigner().SignatureAlgorithm)
	return signingTime, timestamp, nil

}

// VerifyPkcs7 is an own implementation based on pkcs7.verifyWithChain.
// This version allows to do the expiration checks against the timestamp (instead of against the current time or the signing time)
func VerifyPkcs7(p7 *pkcs7.PKCS7, signingTime time.Time, content []byte, trustedAnchors *x509.CertPool) (bool, error) {

	signers := p7.Signers

	// Return false if there is no signers or more than one signer
	if len(signers) != 1 {
		return false, errors.New("signature must have exactly one signer")
	}

	// I expect there is only one signer
	signerInfo := signers[0]

	// The message digest is one of the authenticated attributes
	authAttrs := signerInfo.AuthenticatedAttributes

	// Find the message digest
	var digest []byte
	for _, authAttr := range authAttrs {

		// SigningTime is 1.2.840.113549.1.9.5
		// It should not part of the authenticated attributes for a PAdES signature
		// LATER DEBUG
		// log.Printf("%d authenticated attribute type %s found in signature\n", i, authAttr.Type)

		// Is this attribute the MessageDigest?
		var OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

		if authAttr.Type.Equal(OIDAttributeMessageDigest) {
			// Unmarshall authenticated attribute (digest)
			_, err := asn1.Unmarshal(authAttr.Value.Bytes, &digest)
			if err != nil {
				return false, err
			}
			log.Printf("extracted digest from pkcs7")
		}
	} // end for auth attributes

	// Make sure the digest was among the auth attrs
	if len(digest) == 0 {
		return false, errors.New("message digest not found among authenticated attributes")
	}

	// Find out the digest algorithm
	// hash := crypto.SHA256
	hashp, err := getDigestAlgorithmFromOid(signerInfo.DigestAlgorithm.Algorithm)
	if err != nil {
		return false, err
	}

	// TODO Do I need this?
	hash := *hashp
	// log.Println(" ***** digest algorithm: ", hash)

	// TODO For some reason, for "timestamp only" this is not working
	// Calculate message hash
	h := hash.New()
	h.Write(content)
	computed := h.Sum(make([]byte, 0))

	if bytes.Compare(computed, digest) == 0 {
		log.Println("computed hash == digest on pkcs7")

	} else {
		log.Println("ERROR: Computed != Digest")
		log.Println("Expected: ", digest)
		log.Println("Computed: ", computed)
		return false, errors.New("computed digest does not match expected digest")
	}

	signerCertificate := p7.GetOnlySigner()
	// LATER there is no signerInfo.Certificate? That would be better than using the function getOnlySigner()

	// Timestamp verification: make sure the certificate was valid in the momemnt of time indicated by the timestamp
	if signingTime.Before(signerCertificate.NotBefore) || signingTime.After(signerCertificate.NotAfter) {
		return false, errors.New("signer certificate was not valid as for the timestamped signing time")
	}
	log.Println("the signing certificate was valid as for the timestamped signing time")

	// Get intermediates from the signature. Only the roots are passed as a parameter.
	intermediates, err := getIntermediates(p7)
	if err != nil {
		return false, nil
	}
	// Signer Certificate and Chain verification against the provided truststores
	verifyOptions := x509.VerifyOptions{
		Roots:         trustedAnchors,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   signingTime,
	}

	// Signature verification
	_, err = signerCertificate.Verify(verifyOptions)

	if err != nil {
		return false, err
	}
	log.Printf("signer certificate verification was succesfull")

	// Signature verification
	// TODO Review checkSignature() in pkcs7.verify(). Is everything covered here?

	// If no error so far, the verification was fine
	return true, nil
}

// ExtractRevocationInfo extracts the RevocationInformation from the signature
func ExtractRevocationInfo(signature *pkcs7.PKCS7) (*ocsp.Response, *pkix.CertificateList, error) {

	var ocspResponse *ocsp.Response
	var crl *pkix.CertificateList

	signers := signature.Signers
	for i := 0; i < len(signers); i++ {
		signerInfo := signers[i]

		// The RI is embedded in the signature as signed attribute with OID 1.2.840.113583.1.1.8
		authAttrs := signerInfo.AuthenticatedAttributes

		for _, authAttr := range authAttrs {

			// LATER DEBUG
			// log.Printf("authenticated attribute type %s found in signature\n", authAttr.Type)

			if authAttr.Type.String() == "1.2.840.113583.1.1.8" {

				// OCSP
				ocspbytes := authAttr.Value.Bytes

				// ocspbytes is an ASN.1 encoded object, containing CRLs and OCSPs
				var ri revocationInfoArchival
				_, err := asn1.Unmarshal(ocspbytes, &ri)

				if err != nil {
					return ocspResponse, crl, err
				}

				ocspResponse, err = ocsp.ParseResponse(ri.OCSP[0].Bytes, nil)
				log.Printf("ocsp response extracted from pkcs7")
				if err != nil {
					return ocspResponse, crl, err
				}

				crl, err := x509.ParseCRL(ri.CRL[0].Bytes)
				log.Printf("crl extracted from pkcs7")
				if err != nil {
					return ocspResponse, crl, err
				}

				// Either the CRL or the OCSP might be empty, but not both of them
				if len(ri.OCSP) == 0 && len(ri.CRL) == 0 {
					return ocspResponse, crl, errors.New("both ocsp array and crl array are empty on revocationInfoArchival attribute")
				}

				return ocspResponse, crl, nil
			}
		}
		return ocspResponse, crl, errors.New("revocationInfoArchival attribute not found")
	}
	return ocspResponse, crl, errors.New("revocationInfoArchival attribute not found")
}

// VerifyOcsp validates an OCSP response
func VerifyOcsp(ocspresponse *ocsp.Response) (bool, error) {

	// Check OCSP Response status
	if ocspresponse.Status == ocsp.Revoked {
		return false, errors.New("ocsp response status is: REVOKED")
	} else if ocspresponse.Status != ocsp.Good {
		return false, errors.New("ocsp response status is: NOT valid")
	}

	// Status == ocsp.Good
	log.Printf("ocsp response status is good")
	return true, nil
}

// VerifyCrl checks if the signer certificate is not listed as expired in the CRL
func VerifyCrl(crl *pkix.CertificateList, signature *pkcs7.PKCS7) (bool, error) {

	// Expecting only one signer
	signer := signature.GetOnlySigner()
	if signer == nil {
		return false, errors.New("no signers for timestamp signature")
	}
	serialNumber := signer.SerialNumber

	// Show serial number of revoked certificates
	list := crl.TBSCertList
	revokedlist := list.RevokedCertificates
	if len(revokedlist) == 0 {
		log.Println("list of revoked certificates is empty")

	} else {
		for _, revoked := range revokedlist {
			log.Println("serial number of revoked certificate: ", revoked.SerialNumber)
			if serialNumber != nil {
				// Proof that the given serial number does not match the one on the list
				if serialNumber == revoked.SerialNumber {
					return false, errors.New("signing certificate is revoked according with the CRL")
				} else {
					log.Println("serial number of revoked certificate does not match the signer certificate")
				}
			}
		}
	}
	return true, nil
}

// INTERNAL FUNCTIONS

// getCertificate returns a X.509 certificate from a filepath
func getCertificate(certpath string) (*x509.Certificate, error) {

	var cert *x509.Certificate

	// Read bytes from Root CA certificate file
	rootCaCertBytes, err := ioutil.ReadFile(certpath)
	if err != nil {
		return cert, err
	}

	// Parse X.509 certificate
	cert, err = x509.ParseCertificate(rootCaCertBytes)
	if err != nil {
		return cert, err
	}
	return cert, nil
}

// getIntermediates returns a certpool given a pkcs7 signature
func getIntermediates(p7 *pkcs7.PKCS7) (*x509.CertPool, error) {

	intermediates := x509.NewCertPool()

	// Add all certificates
	for _, cert := range p7.Certificates {
		intermediates.AddCert(cert)
		// log.Println(" ***** Added intermediate ", cert.Subject)
	}
	return intermediates, nil
}

// GetTrustedAnchors returns a certpool given a filepath
func GetTrustedAnchors(pem *string) (*x509.CertPool, error) {

	trustedAnchors := x509.NewCertPool()

	if pem != nil {

		// If the trustedAnchors are provided as a parameter (pem file)
		file, err := ioutil.ReadFile(*pem)
		if err != nil {
			return nil, err
		}

		ok := trustedAnchors.AppendCertsFromPEM(file)
		if !ok {
			return trustedAnchors, errors.New("error parsing cert pool from pem file")
		}

		// log.Println("***** Trusted anchors ", trustedAnchors)

	} else {

		// If the trustedAnchors are NOT passed as a parameter, use the EU list
		trustedAnchors, err := trustlists.EUCertPool(trustlists.Options{})
		if err != nil {
			return trustedAnchors, err
		}

	}
	return trustedAnchors, nil
}

// Local functions

// From crypto/ocsp
var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}

// getDigestAlgorithmFromOid
func getDigestAlgorithmFromOid(oid asn1.ObjectIdentifier) (*crypto.Hash, error) {

	for alg, algOid := range hashOIDs {
		if algOid.Equal(oid) {
			// LATER DEBUG
			// log.Println(" ****** found digest algorithm for oid: ", oid)
			return &alg, nil
		}
	}
	// not found
	return nil, errors.New("digest algorithm oid unknown")
}
