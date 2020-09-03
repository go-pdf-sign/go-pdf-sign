package pdf_sign

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	pdf "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// The RevocationInfo type contains ocsps and crls
type RevocationInfo struct {
	Crl  *pkix.CertificateList
	Ocsp *ocsp.Response
}

// The SignedPdf type holds all relevant information for signature verification
type SignedPdf struct {

	// Content represents the signed content in the pdf
	Content []byte

	// ByteRange defines the portion of the pdf which is signed
	ByteRange pdf.Array

	// IsTimestampOnly is true if the pdf is only timestamped but not signed
	IsTimestampOnly bool

	// Signature is the pkcs7 object holding the signature (PAdES signature)
	Signature *pkcs7.PKCS7

	// Timetamp is the pkcs7 object holding the timestamp (CAdES signature)
	Timestamp *pkcs7.PKCS7

	// SigningTime is the signed time signed holded by the timestamp
	SigningTime time.Time

	// RevocationInfo holds the revocation information associated with the signing certificate
	RevocationInfo RevocationInfo

	// ValidationInfo holds the revocation information associated with the timestamp signing certificate
	ValidationInfo RevocationInfo

	// TrustedAnchors hold the trusted ca certificates for signature validation
	TrustedAnchors *x509.CertPool
}

// Init parses the pdf in the filepath and extract the relevant components for signature verification
func Init(filepath string, trustedAnchorsPem string) (SignedPdf, error) {

	var mypdf SignedPdf

	// Extract pdf context
	context, err := ExtractContext(filepath)
	if err != nil {
		return mypdf, err
	}

	// Extract signature dictionary
	sigdict, err := ExtractSigDict(context)
	if err != nil {
		return mypdf, err
	}

	// EXTRACT BYTE RANGE
	mypdf.ByteRange, err = ExtractByteRange(&sigdict)
	if err != nil {
		return mypdf, err
	}

	// EXTRACT PKCS#7 SIGNATURE
	signatureBytes, err := ExtractSignatureBytes(&sigdict)
	if err != nil {
		return mypdf, err
	}

	// PARSE PKCS7 SIGNATURE
	mypdf.Signature, err = pkcs7.Parse(signatureBytes)
	if err != nil {
		return mypdf, err
	}

	// TIMESTAMP ONLY
	mypdf.IsTimestampOnly = IsTimestampOnly(mypdf.Signature)

	// EXTRACT PKCS#7 TIMESTAMP
	if mypdf.IsTimestampOnly {
		// If the document is only timestamped, the signed timestamp is the signature itself
		mypdf.Timestamp = mypdf.Signature

	} else {
		// If it is a CMS signature, we extract the timestamp
		mypdf.Timestamp, err = ExtractTimestamp(mypdf.Signature)
		if err != nil {
			return mypdf, err
		}
		//log.Printf("timestamp extracted from pkcs7")
	}

	// EXTRACT SIGNING TIME
	mypdf.SigningTime, err = ExtractSigningTime(mypdf.Timestamp)
	if err != nil {
		return mypdf, err
	}

	// EXTRACT CONTENT
	if !mypdf.IsTimestampOnly {
		// For a cms signature, the signed content must be extracted
		mypdf.Content, err = ExtractContent(filepath, mypdf.ByteRange)
		if err != nil {
			return mypdf, err
		}
	}

	// EXTRACT REVOCATION INFO FROM PKCS#7 (only for cms signatures)
	// TODO this function must return a RevocationInfo object
	if !mypdf.IsTimestampOnly {
		mypdf.RevocationInfo.Ocsp, mypdf.RevocationInfo.Crl, err = ExtractRevocationInfo(mypdf.Signature)
		if err != nil {
			return mypdf, err
		}
	}
	// For timestamps, there is only validation info embedded in the document, nothing to extract from the pkcs7

	// EXTRACT VALIDATION INFO FROM PDF
	ocspsbytearray, crlsbytearray, err := ExtractValidationInformation(context)

	// Create array of ocsp responses
	ocsps := make([]*ocsp.Response, len(ocspsbytearray))

	// Each OCSP object is an ASN.1 encoded OCSP response
	for i, ocspstream := range ocspsbytearray {

		// Parse OCSP response
		ocspresponse, err := ocsp.ParseResponse(ocspstream, nil)
		if err != nil {
			return mypdf, err
		}
		// Include parsed ocsp in ocsp array
		ocsps[i] = ocspresponse
	}
	// LATER If I get only the first element, I actually don't need the loop
	mypdf.ValidationInfo.Ocsp = ocsps[0]

	// Create array of crls
	crls := make([]*pkix.CertificateList, len(crlsbytearray))

	for i, crlstream := range crlsbytearray {
		certList, err := x509.ParseCRL(crlstream)
		if err != nil {
			return mypdf, err
		}
		// Include parsed crl in crl array
		crls[i] = certList
	}
	// LATER If I get only the first element, I actually don't need the loop
	mypdf.ValidationInfo.Crl = crls[0]

	// 7. DEFINE TRUSTED ANCHORS
	// If the trusted anchors are not provided, get the european list
	mypdf.TrustedAnchors, err = GetTrustedAnchors(&trustedAnchorsPem)

	return mypdf, nil
}
