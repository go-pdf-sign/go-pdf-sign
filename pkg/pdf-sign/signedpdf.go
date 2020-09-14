package pdf_sign

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	pdf "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// The RevocationInfo type contains a base16-encoded signature and its associated ocsps, crls and certs
type RevocationInfo struct {
	Base16cert string
	Crls       []*pkix.CertificateList
	Ocsps      []*ocsp.Response
	Certs      []*x509.Certificate
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

	// RevocationInfo holds the revocation information embedded in the pkcs7
	RevocationInfo RevocationInfo

	// ValidationInfo holds the revocation information associated with all signatures
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

	var timestampBytes []byte

	// EXTRACT PKCS#7 TIMESTAMP
	if mypdf.IsTimestampOnly {

		// If the document is only timestamped, the signed timestamp is the signature itself
		mypdf.Timestamp = mypdf.Signature
		timestampBytes = signatureBytes

	} else {

		// If it is a CMS signature, we extract the timestamp
		timestampBytes, err = ExtractTimestampBytes(mypdf.Signature)
		if err != nil {
			return mypdf, err
		}
		mypdf.Timestamp, err = pkcs7.Parse(timestampBytes)
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

	// The RI (revocation information = CRLs, OCSP) of the signature are embedded in the CMS object itself
	// Adobe Reader: "The selected certificate is considered valid because it has not been revoked
	// as verified using the Online Certificate Status Protocol (OCSP) response that was embedded in the signature."
	// For PAdES CMS signatures, the RI is embedded in the signature as a signed attribute with OID 1.2.840.113583.1.1.8

	// The RI might not be on the RevocationInfoArchival as assumed below, but it can be embedded in the DSS dictionary directly alongside the VI
	var found bool
	if !mypdf.IsTimestampOnly {
		found, mypdf.RevocationInfo, err = ExtractRevocationInfo(mypdf.Signature)
		if err != nil {
			return mypdf, err
		}

		// If there is no revocation info on the pkcs7, try to extract it from the DSS dictionary (below)

		// EXTRACT REVOCATION INFO FROM PDF (signature)
		// If there was no revocation info on the pkcs7, try to find the ocsp among the validation information (same as for the timestamp)
		if !found {

			// Find out index by checking how many elements the array has
			//index := len(mypdf.ValidationInfo)
			// Extract ValidationInfo for the cms signature
			mypdf.RevocationInfo, err = ExtractValidationInformation(context, signatureBytes)
			if err != nil {
				return mypdf, err
			}
		}
	}

	// EXTRACT VALIDATION INFO FROM PDF (timestamp)

	// For timestamps, there is only validation info embedded in the document, nothing to extract from the pkcs7
	// The VI (validation information = CRLs, OCSP) included in the document are the ones of the timestamp
	// Adobe Reader: "The selected certificate is considered valid because it has not been revoked
	// as verified using the Online Certificate Status Protocol (OCSP) response that was embedded in the document."

	mypdf.ValidationInfo, err = ExtractValidationInformation(context, nil)
	if err != nil {
		return mypdf, err
	}

	// 7. DEFINE TRUSTED ANCHORS
	// If the trusted anchors are not provided, get the european list
	mypdf.TrustedAnchors, err = GetTrustedAnchors(&trustedAnchorsPem)

	return mypdf, nil
}
