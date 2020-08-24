package pdf_sign

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/ioutil"
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

// ExtractTimestamp extracts the signingTime from the timestamp embedded in the signature
func ExtractTimestamp(signature *pkcs7.PKCS7, trustedAnchors *x509.CertPool) (time.Time, *pkcs7.PKCS7, error) {

	var signingTime time.Time

	// Only 1 signer allowed (LATER: remove the loop below, since it does not make sense anymore)
	if len(signature.Signers) != 1 {
		return signingTime, nil, errors.New("there must be only one signer on the pkcs7")
	}

	// TODO What if the pkcs7 is a timestamp instead of a cms signature?

	// The timestamp is included in the "SignerInfo" as an unauthenticated attribute
	signers := signature.Signers
	for i := 0; i < len(signers); i++ {
		signerInfo := signers[i]

		// The timestamp is an "unauthenticated attribute"
		// The timestamp is a CADES signature of the "authenticated attributes"
		unauthAttrs := signerInfo.UnauthenticatedAttributes
		for _, unauthAttr := range unauthAttrs {

			// LATER LOG unauthAttr
			// fmt.Printf(" ***** LOG: %d unauthenticated attribute type %s found in timestamp\n", i, unauthAttr.Type)

			// Timestamp should be 1.2.840.113549.1.9.16.2.14 according to RFC3161 (Appendix A)
			if unauthAttr.Type.String() == "1.2.840.113549.1.9.16.2.14" {

				// The signingTime must be the one corresponding to the AuthAttribute of the timestamp
				// The timestamp is a CADES signature
				timestamp, err := pkcs7.Parse(unauthAttr.Value.Bytes)
				if err != nil {
					return signingTime, timestamp, err
				}

				var OIDAttributeSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
				var signingTimeBytes []byte

				// Find signingTime
				for _, signer := range timestamp.Signers {

					for _, authattr := range signer.AuthenticatedAttributes {

						if authattr.Type.Equal(OIDAttributeSigningTime) {
							signingTimeBytes = authattr.Value.Bytes
						}
					}
				}

				asn1.Unmarshal(signingTimeBytes, &signingTime)

				// Verify timestamp signature
				// TODO content? Where does timestamp.Content come from?
				_, err = VerifyPkcs7(timestamp, signingTime, timestamp.Content, trustedAnchors)
				if err != nil {
					return signingTime, timestamp, err
				}

				return signingTime, timestamp, nil
			}
		}
	}
	return signingTime, nil, errors.New("timestamp not found")
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

		// Is this attribute the MessageDigest?
		var OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

		if authAttr.Type.Equal(OIDAttributeMessageDigest) {
			// Unmarshall authenticated attribute (digest)
			_, err := asn1.Unmarshal(authAttr.Value.Bytes, &digest)
			if err != nil {
				return false, err
			}
		}
	} // end for auth attributes

	// Make sure the digest was among the auth attrs
	if len(digest) == 0 {
		return false, errors.New("message digest not found among authenticated attributes")
	}

	// Calculate message hash
	// TODO Assuming signerInfo.digestAlgorithm is SHA256. I need to fix this.
	hash := crypto.SHA256
	h := hash.New()
	h.Write(content)
	computed := h.Sum(make([]byte, 0))

	if bytes.Compare(computed, digest) == 0 {
		// fmt.Println(" ***** Computed == Digest")

	} else {
		// fmt.Println("Computed != Digest")
		// fmt.Println("Expected: ", digest)
		// fmt.Println("Computed: ", computed)
		return false, errors.New("computed digest does not match expected digest")
	}

	signerCertificate := p7.GetOnlySigner()
	// LATER there is no signerInfo.Certificate? That would be better than using the function getOnlySigner()

	// Timestamp verification: make sure the certificate was valid in the momemnt of time indicated by the timestamp
	if signingTime.Before(signerCertificate.NotBefore) || signingTime.After(signerCertificate.NotAfter) {
		return false, errors.New("signer certificate was not valid as for the timestamped signing time")
	}

	// Trusted Anchors (usually the Root CA certificates)
	// LATER I don't like how I'm handling the parameters here
	/*
		trustedAnchors, err := getTrustedAnchors(&trustedAnchorsPem)
		if err != nil {
			return false, err
		}
	*/

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

			// LATER LOG authAttr
			// fmt.Printf(" ***** LOG: authenticated attribute type %s found in signature\n", authAttr.Type)

			if authAttr.Type.String() == "1.2.840.113583.1.1.8" {

				// OCSP
				ocspbytes := authAttr.Value.Bytes

				// ocspbytes is an ASN.1 encoded object, containing CRLs and OCSPs
				var ri revocationInfoArchival
				_, err := asn1.Unmarshal(ocspbytes, &ri)

				if err != nil {
					return ocspResponse, crl, err
				}

				if len(ri.OCSP) == 0 {
					return ocspResponse, crl, errors.New("ocsp array is empty on revocationInfoArchival attribute")
				}
				ocspResponse, err = ocsp.ParseResponse(ri.OCSP[0].Bytes, nil)
				if err != nil {
					return ocspResponse, crl, err
				}

				// CRL
				crl, err := x509.ParseCRL(ri.CRL[0].Bytes)
				if err != nil {
					return ocspResponse, crl, err
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
		//fmt.Println(" ***** LOG list is empty (LTV): no revoked certificates")

	} else {
		for _, revoked := range revokedlist {
			// fmt.Println(" ***** LOG serial number of revoked certificate: ", revoked.SerialNumber)
			if serialNumber != nil {
				// Proof that the given serial number does not match the one on the list
				if serialNumber == revoked.SerialNumber {
					return false, errors.New("signing certificate is revoked according with the CRL")
				} else {
					// fmt.Println(" **** LOG serial number of revoked certificate does not match the one provided")
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
	// TODO PSS algorithm seems not to be supported
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
		// fmt.Println(" ***** Added intermediate ", cert.Subject)
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

		// fmt.Println("***** Trusted anchors ", trustedAnchors)

	} else {

		// If the trustedAnchors are NOT passed as a parameter, use the EU list
		trustedAnchors, err := trustlists.EUCertPool(trustlists.Options{})
		if err != nil {
			return trustedAnchors, err
		}

	}
	return trustedAnchors, nil
}
