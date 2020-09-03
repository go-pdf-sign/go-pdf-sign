package pdf_sign

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"log"
	"os"
	"time"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	pdf "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// Struct for unmarshal of signed attribute RevocationInfoArchival
type revocationInfoArchival struct {
	CRL          []asn1.RawValue `asn1:"tag:0,optional"`
	OCSP         []asn1.RawValue `asn1:"tag:1,optional"`
	OtherRevInfo []asn1.RawValue `asn1:"tag:2,optional"`
}

// ExtractContext extracts the PDF context from the PDF found on the given path
func ExtractContext(path string) (*pdf.Context, error) {

	context, err := pdfcpu.ReadContextFile(path)
	if err != nil {
		return nil, err
	}
	return context, nil
}

// ExtractByteRange accesses the RootDictionary of the PDF and extracts the Byte Range
// ByteRange: portion of the document included in the signature
func ExtractByteRange(sigdict *pdf.Dict) (pdf.Array, error) {

	var byteRangeArray pdf.Array

	// Access ByteRange to get the bytes which will form the hash
	byteRange, found := sigdict.Find("ByteRange")
	if !found {
		return byteRangeArray, errors.New("byte range not found")
	}

	// byteRange is an array - cast to pdf.Array
	byteRangeArray = byteRange.(pdf.Array)

	log.Println("parse: bytearray is ", byteRangeArray)

	return byteRangeArray, nil
}

// ExtractSignatureBytes accesses the RootDictionary of the PDF and extracts the pkcs7 signature object
func ExtractSignatureBytes(sigdict *pdf.Dict) ([]byte, error) {

	// Access "Contents" on the Signature Dictionary
	contents, found := sigdict.Find("Contents")
	if !found {
		return nil, errors.New("contents not found")
	}

	// Read signature bytes
	contentsHexLiteral := contents.(pdf.HexLiteral)

	signatureBytes, err := contentsHexLiteral.Bytes()
	if err != nil {
		return nil, err
	}

	log.Println("parse: found pkcs7 signature")

	return signatureBytes, nil
}

// ExtractSigDict extracts the signature dictionary from the given pdf context
func ExtractSigDict(context *pdf.Context) (pdf.Dict, error) {

	// Access Root Dictionary (pdf.Dict)
	rootdict := context.RootDict
	log.Println("parse: root dictionary found in pdf")

	// Access AcroForm Dictionary (pdf.Object)
	acroformobj, found := rootdict.Find("AcroForm")

	if !found {
		return nil, errors.New("acroform dictionary not found")
	}
	log.Println("parse: acroform dictionary found in pdf")

	// Cast acroformobj (which is pdf.Object or an indirect reference) to pdf.Dict, so we can search for "Fields"
	acroformdict, err := context.DereferenceDict(acroformobj)
	if err != nil {
		return nil, err
	}

	// Access Fields (array?)
	fields, found := acroformdict.Find("Fields")

	if !found {
		return nil, errors.New("fields not found in acroform dictionary")
	}

	// Resolve Fields reference
	fieldsarray, err := context.DereferenceArray(fields)
	if err != nil {
		return nil, errors.New("can't dereference fields array")
	}

	// We need to access the first position of the array fields
	value := fieldsarray[0]

	indirectreference, ok := value.(pdf.IndirectRef)
	if !ok {
		return nil, errors.New("can't cast indirect reference")
	}

	// Dereference indirect reference to access the dictionary
	dict, err := context.DereferenceDict(indirectreference)
	if err != nil {
		return nil, errors.New("can't dereference dictionary")
	}

	// Access V
	v, found := dict.Find("V")
	if !found {
		return nil, errors.New("v not found")
	}

	// Resolve V reference to get Signature Dictionary
	sigdict, err := context.DereferenceDict(v)
	if err != nil {
		return nil, errors.New("can't dereference Signature dictionary")
	}
	log.Println("parse: signature dictionary found in pdf")
	return sigdict, nil
}

// ExtractContent returns the hash of the document, given the byte range
func ExtractContent(path string, byteRangeArray pdf.Array) ([]byte, error) {

	// The byte range indicates the portion of the document to be signed

	// The byteRangeArray has four positions
	// Position 0 indicates the beginning
	// Between positions 1 and 2 is the signature
	// Position 3 indicates the length from the signature to the end of the file
	posBeforeSig := byteRangeArray[0].(pdf.Integer)
	lenBeforeSig := byteRangeArray[1].(pdf.Integer)
	posAfterSig := byteRangeArray[2].(pdf.Integer)
	lenAfterSig := byteRangeArray[3].(pdf.Integer)

	// Open pdf file
	pdfFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Read the document portion located before the signature
	byteSliceBefore := make([]byte, lenBeforeSig)
	pdfFile.ReadAt(byteSliceBefore, int64(posBeforeSig))

	// Read the document portion located after the signature
	byteSliceAfter := make([]byte, lenAfterSig)
	pdfFile.ReadAt(byteSliceAfter, int64(posAfterSig))

	// Concatenate the two read portions
	bytes := append(byteSliceBefore, byteSliceAfter...)
	return bytes, nil

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

			log.Println("parse: timestamp found in pkcs7")

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

			log.Println("parse: signing time is ", signingTime)
			return signingTime, nil
		}
	}

	// No signing time found
	return signingTime, errors.New("no signing time in pkcs7")

}

// IsTimestampOnly returns true if the signature is a timestamp (instead of a CMS signature)
func IsTimestampOnly(signature *pkcs7.PKCS7) bool {

	// LATER Find a better way to find out if it's at timestamp or a cms

	// Try to extract the signingTime
	// If not found: it's a cms signature (PAdES)
	// If found: it's a timestamp (CAdES)

	_, err := ExtractSigningTime(signature)
	if err != nil {
		log.Println("parse: the pkcs7 is a cms signature")
		return false
	}
	log.Println("parse: the pkcs7 is a timestamp")
	return true
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

				log.Printf("parse: revocationinfo found in pkcs7")

				// OCSP
				ocspbytes := authAttr.Value.Bytes

				// ocspbytes is an ASN.1 encoded object, containing CRLs and OCSPs
				var ri revocationInfoArchival
				_, err := asn1.Unmarshal(ocspbytes, &ri)

				if err != nil {
					return ocspResponse, crl, err
				}

				if len(ri.OCSP) > 0 {
					ocspResponse, err = ocsp.ParseResponse(ri.OCSP[0].Bytes, nil)
					if err != nil {
						return ocspResponse, crl, err
					}
				}

				if len(ri.CRL) > 0 {
					crl, err := x509.ParseCRL(ri.CRL[0].Bytes)
					if err != nil {
						return ocspResponse, crl, err
					}
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

// ExtractValidationInformation finds and parses the Validation Information embedded in the PDF document
func ExtractValidationInformation(context *pdf.Context) ([][]byte, [][]byte, error) {

	// Access the Root Dictionary
	rootdict := context.RootDict

	// Find DSS Dictionary inside Root Dictionary
	dssdictref, found := rootdict.Find("DSS")
	if !found {
		return nil, nil, errors.New("dss dictionary not found")
	}

	// DSS object is an indirect object pointing to the DSS dictionary
	dssdict, err := context.DereferenceDict(dssdictref)
	if err != nil {
		return nil, nil, err
	}
	log.Println("parse: dss dictionary found in pdf")

	// TODO Eventually this should not be a fatal error here
	// Access OCSPs object
	ocspsobj, found := dssdict.Find("OCSPs")
	if !found {
		return nil, nil, errors.New("ocsp object not found in dss dictionary")
	}

	// OCSPs object is an indirect object pointing to an array
	ocspsarray, err := context.DereferenceArray(ocspsobj)
	if err != nil {
		return nil, nil, err
	}

	ocspsbytes := make([][]byte, len(ocspsarray))

	// Iterate through the ocsp list
	for i, ocsparrayelement := range ocspsarray {

		// Each element on the array is an indirect object pointing to the OCSP stream dictionary
		arrayElement := ocsparrayelement.(pdf.IndirectRef)

		ocspbyte, err := pdf.ExtractStreamData(context, arrayElement.ObjectNumber.Value())
		if err != nil {
			return nil, nil, err
		}
		ocspsbytes[i] = ocspbyte
	}

	// Access CRLs object
	crlsobj, found := dssdict.Find("CRLs")
	if !found {
		return ocspsbytes, nil, errors.New("crl object not found in dss dictionary")
	}

	crlsarray, err := context.DereferenceArray(crlsobj)
	if err != nil {
		return nil, nil, err
	}

	crlsbytes := make([][]byte, len(crlsarray))

	// Iterate throw the CRLs on the array and access stream dictionary
	for i, crlarrayelement := range crlsarray {

		// The element on the array is an indirect object pointing to the CRL stream dictionary
		arrayElement := crlarrayelement.(pdf.IndirectRef)

		crlstream, err := pdf.ExtractStreamData(context, arrayElement.ObjectNumber.Value())
		if err != nil {
			return nil, nil, err
		}

		crlsbytes[i] = crlstream

	}
	return ocspsbytes, crlsbytes, nil
}
