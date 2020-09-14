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

// VerifyPkcs7 is an own implementation based on pkcs7.verifyWithChain.
// This version allows to do the expiration checks against the timestamp (instead of against the current time or the signing time)
func VerifyPkcs7(p7 *pkcs7.PKCS7, signingTime time.Time, content []byte, validationInfo RevocationInfo, trustedAnchors *x509.CertPool) (bool, error) {

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
			log.Printf("verify: extracted digest from pkcs7")
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
	hash := *hashp

	// Calculate message hash
	h := hash.New()
	h.Write(content)
	computed := h.Sum(make([]byte, 0))

	if bytes.Compare(computed, digest) == 0 {
		log.Println("verify: computed hash == digest on pkcs7")

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
	log.Println("verify: the signing certificate was valid as for the timestamped signing time")

	// Get intermediates from the signature. Only the roots are passed as a parameter.
	intermediates, err := getIntermediates(p7, validationInfo)
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
	log.Printf("verify: signer certificate verification was succesfull")

	// LATER verify all certificates in chain and not only the signing certificate

	// If no error so far, the verification was fine
	return true, nil
}

// VerifyRevocationInfo checks:
// - that the status of the ocsp response is GOOD
// - that the signing certificate is not revoked according to the crl
func VerifyRevocationInfo(revocationInfo RevocationInfo, signature *pkcs7.PKCS7) (bool, error) {

	foundOcsp := len(revocationInfo.Ocsps) > 0
	if foundOcsp {

		// LATER Is this correct? Is it possible to have more than one ocsp response here?
		// Take first ocsp from the array
		ocsp := revocationInfo.Ocsps[0]
		//fmt.Println("LEN OF OCSPS (VerifyRevocationInfo) is ", len(revocationInfo.Ocsps))

		// Validate ocsp response
		err := VerifyOcsp(ocsp)
		if err != nil {
			return false, err
		}

	} else {
		log.Println("there is no ocsp to validate")
	}

	// LATER Is this correct? Is it possible to have more than one crl here?
	foundCrl := len(revocationInfo.Ocsps) > 0
	if foundCrl {
		// Take first crl from the array
		crl := revocationInfo.Crls[0]

		// Validate signing certificate against CRL
		err := VerifyCrl(crl, signature)
		if err != nil {
			return false, err
		}

	} else {
		log.Println("there is no crl to validate against")
	}

	// Return true if either ocsp or crl was found, false otherweise
	if !foundCrl && !foundOcsp {
		return false, nil
	}
	return true, nil

}

// VerifyOcsp validates an OCSP response
func VerifyOcsp(ocspresponse *ocsp.Response) error {

	// Check OCSP Response status
	if ocspresponse.Status == ocsp.Revoked {
		return errors.New("ocsp response status is: REVOKED")
	} else if ocspresponse.Status != ocsp.Good {
		return errors.New("ocsp response status is: NOT valid")
	}

	// Status == ocsp.Good
	log.Printf("verify: ocsp response status is GOOD")
	return nil
}

// VerifyCrl checks if the signer certificate is not listed as expired in the CRL
func VerifyCrl(crl *pkix.CertificateList, signature *pkcs7.PKCS7) error {

	// Expecting only one signer
	signer := signature.GetOnlySigner()

	if signer == nil {
		return errors.New("no signers for timestamp signature")
	}
	serialNumber := signer.SerialNumber

	// Show serial number of revoked certificates
	list := crl.TBSCertList
	revokedlist := list.RevokedCertificates
	if len(revokedlist) == 0 {
		log.Println("verify: list of revoked certificates is empty")

	} else {
		for _, revoked := range revokedlist {
			// log.Println("serial number of revoked certificate: ", revoked.SerialNumber)
			if serialNumber != nil {
				// Proof that the given serial number does not match the one on the list
				if serialNumber == revoked.SerialNumber {
					return errors.New("signing certificate is revoked according with the CRL")
				}
				//else {
				//	log.Println("verify: serial number of revoked certificate does not match the signer certificate")
				//}
			}
		}
		log.Println("verify: signing certificate NOT expired according with crl")
	}
	return nil
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

	} else {

		// If the trustedAnchors are NOT passed as a parameter, use the EU list
		trustedAnchors, err := trustlists.EUCertPool(trustlists.Options{})
		if err != nil {
			return trustedAnchors, err
		}

	}
	return trustedAnchors, nil
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
func getIntermediates(p7 *pkcs7.PKCS7, validationInfo RevocationInfo) (*x509.CertPool, error) {

	intermediates := x509.NewCertPool()

	// Add all certificates from pkcs7
	for _, cert := range p7.Certificates {
		intermediates.AddCert(cert)
		// log.Println(" ***** Added intermediate ", cert.Subject)
	}

	// Add all certificates from validationInfo (if any)
	if len(validationInfo.Certs) > 0 {
		log.Println("verify: adding vri certificates for pkcs7 verification")
	}
	//else {
	//	log.Println("verify: no certificates in vri object")
	//}
	for _, cert := range validationInfo.Certs {
		intermediates.AddCert(cert)
		//log.Println(" ***** Added intermediate from VRI ", cert.Subject)
	}

	return intermediates, nil
}

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
			return &alg, nil
		}
	}
	// not found
	return nil, errors.New("digest algorithm oid unknown")
}
