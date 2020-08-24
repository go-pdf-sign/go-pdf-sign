package main

import (
	"errors"
	"fmt"
	"os"

	pdf_sign "github.com/go-pdf-sign/go-pdf-sign/pkg/pdf-sign"
)

// Main function: extracts, parses and validates the CMS signature and the additional Validation Information
// Arguments: 1. The filepath to the PDF document
// 2. The filepath to the certificate file of the timestamp service
func main() {

	// TODO Make cacerts optional
	if len(os.Args) < 2 {
		fmt.Printf("Arguments: %d/n", len(os.Args))
		panic("usage: xxx <test.pdf> [<cacerts.pem>]")
	}

	// Extract CMS signature from the PDF
	signature, byteRangeArray, err := pdf_sign.ExtractSignature(os.Args[1])
	if err != nil {
		fmt.Println(" *** EXTRACT SIGNATURE FAILED")
		panic(err)
	} else {
		fmt.Println(" *** extract signature succeeded")
		fmt.Println(" *** byterange: ", byteRangeArray)
	}

	// Calculate digest of the document
	content, err := pdf_sign.Contents(os.Args[1], byteRangeArray)
	if err != nil {
		panic(err)
	}

	// EXTRACT and VALIDATE TIMESTAMP
	// The timestamp is included in the "SignerInfo" as an unauthenticated attribute
	// TODO Use flags library instead
	// If the trustedAnchors are provided as parameter, use them. Otherwise the function will return the EU list.
	var trustedAnchorsPem *string
	if len(os.Args) > 2 {
		trustedAnchorsPem = &os.Args[2]
	}
	trustedAnchors, err := pdf_sign.GetTrustedAnchors(trustedAnchorsPem)

	signingTime, timestamp, err := pdf_sign.ExtractTimestamp(signature, trustedAnchors)
	if err != nil {
		// TODO Log / stdout / whatever
		fmt.Println(" *** EXTRACT TIMESTAMP / TIMESTAMP VERIFICATION FAILED")
		panic(err)
	} else {
		fmt.Println(" *** extract timestamp + verification succeeded")
	}
	fmt.Println(" *** (signed) signing time from timestamp: ", signingTime)

	// VALIDATE SIGNATURE
	// I'm implementing my own verify()function. The ones included in pkcs7 package the expiration
	// is always done against the SigningTime or the current time, which is wrong for PADES LTV
	// TODO Review verify() function: do we really need the certificates here?
	_, err = pdf_sign.VerifyPkcs7(signature, signingTime, content, trustedAnchors)

	if err != nil {
		fmt.Println(" *** SIGNATURE VERIFICATION FAILED")
		panic(err)
	} else {
		fmt.Println(" *** signature verification succeeded")
	}

	// 3 REVOCATION CHECKS
	// The RI (revocation information = CRLs, OCSP) of the signature are embedded in the CMS object itself
	// Adobe Reader: "The selected certificate is considered valid because it has not been revoked
	// as verified using the Online Certificate Status Protocol (OCSP) response that was embedded in the signature."

	// For PAdES CMS signatures, the RI is embedded in the signature as a signed attribute with OID 1.2.840.113583.1.1.8
	// TODO Should this function return an array of OCSPResponses? For consistency
	ocspResponse, crl, err := pdf_sign.ExtractRevocationInfo(signature)
	if err != nil {
		fmt.Println(" *** EXTRACT REVOCATION INFO FROM PKCS7 FAILED")
		panic(err)
	} else {
		fmt.Println(" *** found revocation information in signature")
	}

	// Validate OCSP included in the signature (i.e. the OCSP for the signing certificate)
	_, err = pdf_sign.VerifyOcsp(ocspResponse)
	if err != nil {
		fmt.Println(" *** OCSP VERIFICATION FAILED (pkcs7)")
	} else {
		fmt.Printf(" *** ocsp response status is GOOD (pkcs7) for signing certificate: %s\n", ocspResponse.Certificate.Subject)
	}

	// Validate signing certificate against CRL
	ok, err := pdf_sign.VerifyCrl(crl, signature)
	if err != nil {
		panic(err)
	}
	if !ok {
		panic(errors.New("certificate expired according with crl"))
	} else {
		fmt.Println(" *** signing certificate (pkcs7) not expired according with crl")
	}

	// 4 LTV
	// The VI (validation information = CRLs, OCSP) included in the document are the ones of the timestamp
	// Adobe Reader: "The selected certificate is considered valid because it has not been revoked
	// as verified using the Online Certificate Status Protocol (OCSP) response that was embedded in the document."

	// Extract OCSPs and CRLs from the PDF
	// TODO Not sure yet what to do with the CRLs or if I really need them for the validation
	ocsps, crls, err := pdf_sign.ExtractValidationInformation(os.Args[1])

	// Validate OCSP included in the document
	if len(ocsps) == 0 {
		fmt.Println("no ocsp embedded in document")
	}
	for _, ocspResponse := range ocsps {
		_, err := pdf_sign.VerifyOcsp(ocspResponse)
		if err != nil {
			fmt.Println(" *** OCSP VERIFICATION FAILED (LTV)")
			panic(err)
		} else {
			fmt.Println(" *** validation information found in pdf document")
		}

		fmt.Printf(" *** ocsp response status is GOOD (LTV) for signing certificate: %s\n", ocspResponse.Certificate.Subject)
	}

	// Validate CRL included in the document making sure the signing certificate (timestamp) is not revoked
	if len(crls) == 0 {
		fmt.Println("no crls embedded in the document")
	}

	// Either OCSP or CRL should be included in the document, otherwise the PDF is non-LTV
	if len(ocsps) == 0 && len(crls) == 0 {
		panic(errors.New("no validation information embedded in the PDF"))
	}

	for _, crl := range crls {
		ok, err := pdf_sign.VerifyCrl(crl, timestamp)

		if err != nil {
			panic(err)
		}

		if !ok {
			panic(errors.New("certificate expired according with crl"))
		} else {
			fmt.Println(" *** signing certificate (LTV) not expired according with crl")
		}
	}
}
