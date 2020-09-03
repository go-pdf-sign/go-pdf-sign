package main

import (
	"fmt"
	"log"
	"os"

	pdf_sign "github.com/go-pdf-sign/go-pdf-sign/pkg/pdf-sign"
)

// Main function: extracts, parses and validates the CMS signature and the additional Validation Information
// Arguments:
// 1. The filepath to the PDF document
// 2. The filepath to a pem certificate file with the trusted anchors (optional)
func main() {

	if len(os.Args) < 2 {
		fmt.Printf("Arguments: %d/n", len(os.Args))
		fmt.Printf("Usage: xxx <test.pdf> [<cacerts.pem>]")
	}

	// Cacerts arg is optional
	var trustanchorspem string
	if len(os.Args) == 3 {
		trustanchorspem = os.Args[2]
	}

	/*
		// Uncomment to output the logs to a file instead of the standard output
		logfile, err := os.OpenFile("signedpdf.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Println("can't create logfile: logging to stdout")
		} else {
			log.SetOutput(logfile)
		}
	*/

	// Parse all verification relevant elements from the signed pdf file
	mypdf, err := pdf_sign.Init(os.Args[1], trustanchorspem)
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: parse signed pdf failed")
	}
	log.Println("SUCCESS: INIT PDF")

	// Set log output back to console
	// log.SetOutput(os.Stderr)

	// 1. VALIDATE TIMESTAMP
	_, err = pdf_sign.VerifyPkcs7(mypdf.Timestamp, mypdf.SigningTime, mypdf.Timestamp.Content, mypdf.TrustedAnchors)
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: timestamp verification failed")
	} else {
		log.Println("SUCCESS: TIMESTAMP VERIFICATION")
	}

	// 2. VALIDATE SIGNATURE
	if !mypdf.IsTimestampOnly {
		_, err = pdf_sign.VerifyPkcs7(mypdf.Signature, mypdf.SigningTime, mypdf.Content, mypdf.TrustedAnchors)

		if err != nil {
			log.Println(err)
			log.Fatalln("ERROR: signature verification failed")

		} else {
			log.Println("SUCCESS: SIGNATURE VERIFICATION")
		}
	}

	log.Println("INFO: sign algorithm: ", mypdf.Signature.GetOnlySigner().SignatureAlgorithm)

	// 3 REVOCATION INFORMATION

	// The RI (revocation information = CRLs, OCSP) of the signature are embedded in the CMS object itself
	// Adobe Reader: "The selected certificate is considered valid because it has not been revoked
	// as verified using the Online Certificate Status Protocol (OCSP) response that was embedded in the signature."

	// For PAdES CMS signatures, the RI is embedded in the signature as a signed attribute with OID 1.2.840.113583.1.1.8

	// Validate OCSP included in the signature (i.e. the OCSP for the signing certificate)
	if !mypdf.IsTimestampOnly {

		_, err := pdf_sign.VerifyRevocationInfo(mypdf.RevocationInfo, mypdf.Signature)
		if err != nil {
			log.Println(err)
			log.Fatalln("ERROR: revocation information verification failed (pkcs7)")
		}
		log.Println("SUCCESS: REVOCATION INFORMATION VERIFICATION")

	} else {
		log.Println("INFO: timestamp only (no revocation information in pkcs7 to verify)")
	}

	// 4 LTV (Validation Information)
	// The VI (validation information = CRLs, OCSP) included in the document are the ones of the timestamp
	// Adobe Reader: "The selected certificate is considered valid because it has not been revoked
	// as verified using the Online Certificate Status Protocol (OCSP) response that was embedded in the document."

	// Either OCSP or CRL should be included in the document, otherwise the PDF is non-LTV
	if mypdf.ValidationInfo.Ocsp == nil && mypdf.ValidationInfo.Crl == nil {
		log.Fatalf("ERROR: no validation information embedded in PDF")
	}
	_, err = pdf_sign.VerifyRevocationInfo(mypdf.ValidationInfo, mypdf.Signature)
	if err != nil {
		log.Println(err)
		log.Fatalln("ERROR: validation information verification failed (ltv)")
	}
	log.Println("SUCCESS: VALIDATION INFORMATION VERIFICATION (LTV)")
}
