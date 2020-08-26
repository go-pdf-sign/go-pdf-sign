package main

import (
	"fmt"
	"log"
	"os"
	"time"

	pdf_sign "github.com/go-pdf-sign/go-pdf-sign/pkg/pdf-sign"
	"go.mozilla.org/pkcs7"
)

// Main function: extracts, parses and validates the CMS signature and the additional Validation Information
// Arguments: 1. The filepath to the PDF document
// 2. The filepath to the certificate file of the timestamp service
func main() {

	// Cacerts arg is optional
	if len(os.Args) < 2 {
		fmt.Printf("Arguments: %d/n", len(os.Args))
		fmt.Printf("Usage: xxx <test.pdf> [<cacerts.pem>]")
	}

	// Extract CMS signature from the PDF
	signature, byteRangeArray, err := pdf_sign.ExtractSignatureFromPath(os.Args[1])
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: extracting signature failed")
	} else {
		log.Println("signature found in PDF")
		log.Println("byterange: ", byteRangeArray)
	}

	// Calculate digest of the document
	content, err := pdf_sign.Contents(os.Args[1], byteRangeArray)
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: can't calculate content digest")
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

	// TODO isTimestamp? if YES -> skip extractTimestamp
	// Is the pdf only timestamped?
	isTimestampOnly, err := pdf_sign.IsTimestampOnly(signature)
	if err != nil {
		log.Fatalln(err)
	}

	var signingTime time.Time
	var timestamp *pkcs7.PKCS7
	if !isTimestampOnly {

		log.Println("cms signature: proceed with timestamp extraction and verification")
		signingTime, timestamp, err = pdf_sign.ExtractAndVerifyTimestamp(signature, trustedAnchors)
		if err != nil {
			log.Println(err)
			log.Fatalln("ERROR: extract timestamp or timestamp verification failed")
		} else {
			log.Println("success: timestamp verification")
		}
		// log.Println("(signed) signing time from timestamp: ", signingTime)

	} else {
		log.Println("timestamp only: skipping timestamp extraction and verification.")
		signingTime, err = pdf_sign.ExtractSigningTime(signature)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// VALIDATE SIGNATURE
	// I'm implementing my own verify()function. The ones included in pkcs7 package the expiration
	// is always done against the SigningTime or the current time, which is wrong for PADES LTV
	// TODO Review verify() function: do we really need the certificates here?
	_, err = pdf_sign.VerifyPkcs7(signature, signingTime, content, trustedAnchors)

	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: signature verification failed")
	} else {
		log.Println("success: signature verification")
	}

	// 3 REVOCATION CHECKS
	// The RI (revocation information = CRLs, OCSP) of the signature are embedded in the CMS object itself
	// Adobe Reader: "The selected certificate is considered valid because it has not been revoked
	// as verified using the Online Certificate Status Protocol (OCSP) response that was embedded in the signature."

	// For PAdES CMS signatures, the RI is embedded in the signature as a signed attribute with OID 1.2.840.113583.1.1.8
	// TODO Should this function return an array of OCSPResponses? For consistency
	ocspResponse, crl, err := pdf_sign.ExtractRevocationInfo(signature)
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: extract revocation info from pkcs7 failed")
	} else {
		log.Println("revocation information is included in the signature")
	}

	// Validate OCSP included in the signature (i.e. the OCSP for the signing certificate)
	_, err = pdf_sign.VerifyOcsp(ocspResponse)
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: ocsp verification failed (pkcs7)")
	} else {
		log.Println("success: ocsp response status is GOOD (pkcs7)")
	}

	// Validate signing certificate against CRL
	ok, err := pdf_sign.VerifyCrl(crl, signature)
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: crl verification failed")
	}
	if !ok {
		log.Fatalln("ERROR: signing certificate expired according with crl")
	} else {
		log.Println("success: signing certificate (pkcs7) NOT expired according with crl")
	}

	// 4 LTV
	// The VI (validation information = CRLs, OCSP) included in the document are the ones of the timestamp
	// Adobe Reader: "The selected certificate is considered valid because it has not been revoked
	// as verified using the Online Certificate Status Protocol (OCSP) response that was embedded in the document."

	// Extract OCSPs and CRLs from the PDF
	ocsps, crls, err := pdf_sign.ExtractValidationInformation(os.Args[1])
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: failed to extract validation information from pdf")
	}

	// Validate OCSP included in the document
	if len(ocsps) == 0 {
		log.Println("no ocsp embedded in pdf")
	}
	for _, ocspResponse := range ocsps {
		_, err := pdf_sign.VerifyOcsp(ocspResponse)
		if err != nil {
			log.Println(err)
			log.Fatalln("ERROR: ocsp verification failed (ltv)")
		} else {
			log.Println("validation information found in pdf")
		}

		log.Println("success: ocsp response status is GOOD (ltv)")
	}

	// Validate CRL included in the document making sure the signing certificate (timestamp) is not revoked
	if len(crls) == 0 {
		log.Println("no crls embedded in pdf")
	}

	// Either OCSP or CRL should be included in the document, otherwise the PDF is non-LTV
	if len(ocsps) == 0 && len(crls) == 0 {
		log.Fatalf("ERROR: no validation information embedded in PDF")
	}

	for _, crl := range crls {
		ok, err := pdf_sign.VerifyCrl(crl, timestamp)

		if err != nil {
			log.Println(err)
			log.Fatalln("ERROR: crl verification failed")
		}

		if !ok {
			log.Fatalf("ERROR: signing certificate (ltv) expired according with crl")
		} else {
			log.Println("success: signing certificate (ltv) NOT expired according with crl")
		}
	}
}
