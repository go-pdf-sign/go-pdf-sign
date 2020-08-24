package pdf_sign

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"os"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	pdf "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// ExtractSignature accesses the RootDictionary of the PDF and extract:
// - The CMS signature (as a pkcs7 object)
// - The Byte Range (portion of the document included in the signature)
func ExtractSignature(path string) (*pkcs7.PKCS7, pdf.Array, error) {

	var byteRangeArray pdf.Array

	// TODO falls signature in memory wäre, hätte man kein File
	// PDF File reader
	context, err := pdfcpu.ReadContextFile(path)
	if err != nil {
		return nil, byteRangeArray, err
	}

	// Access Root Dictionary (pdf.Dict)
	rootdict := context.RootDict

	// Access AcroForm Dictionary (pdf.Object)
	acroformobj, found := rootdict.Find("AcroForm")

	if !found {
		return nil, byteRangeArray, errors.New("acroform dictionary not found")
	}

	// Cast acroformobj (which is pdf.Object or an indirect reference) to pdf.Dict, so we can search for "Fields"
	acroformdict, err := context.DereferenceDict(acroformobj)
	if err != nil {
		return nil, byteRangeArray, err
	}

	// Access Fields (array?)
	fields, found := acroformdict.Find("Fields")

	if !found {
		return nil, byteRangeArray, errors.New("fields not found in acroform dictionary")
	}

	// Resolve Fields reference
	fieldsarray, err := context.DereferenceArray(fields)
	if err != nil {
		return nil, byteRangeArray, errors.New("can't dereference fields array")
	}

	// We need to access the first position of the array fields
	value := fieldsarray[0]

	// Which aparently is a reference to the ?? dictionary
	// TODO Confused. Fix comment and error message.
	indirectreference, ok := value.(pdf.IndirectRef)
	if !ok {
		return nil, byteRangeArray, errors.New("can't cast indirect reference")
	}

	// Dereference indirect reference to access the dictionary
	// TODO Confused. Fix comment and error message.
	dict, err := context.DereferenceDict(indirectreference)
	if err != nil {
		return nil, byteRangeArray, errors.New("can't dereference dictionary")
	}

	// Access V
	v, found := dict.Find("V")
	if !found {
		return nil, byteRangeArray, errors.New("v not found")
	}

	// Resolve V reference to get Signature Dictionary
	sigdict, err := context.DereferenceDict(v)
	if err != nil {
		return nil, byteRangeArray, errors.New("can't dereference Signature dictionary")
	}

	// Access "Contents" on the Signature Dictionary
	contents, found := sigdict.Find("Contents")
	if !found {
		return nil, byteRangeArray, errors.New("contents not found")
	}

	// Read signature bytes
	contentsHexLiteral := contents.(pdf.HexLiteral)

	signatureBytes, err := contentsHexLiteral.Bytes()
	if err != nil {
		return nil, byteRangeArray, err
	}

	// Parse CMS signature (the pkcs7 function "Parse" requires the whole document as a parameter)
	p7, err := pkcs7.Parse(signatureBytes)
	if err != nil {
		return nil, byteRangeArray, err
	}

	// Access ByteRange to get the bytes which will form the hash
	byteRange, found := sigdict.Find("ByteRange")
	if !found {
		return nil, byteRangeArray, err
	}

	// byteRange is an array - cast to pdf.Array
	byteRangeArray = byteRange.(pdf.Array)

	return p7, byteRangeArray, nil
}

// Contents returns the hash of the document, given the byte range
func Contents(path string, byteRangeArray pdf.Array) ([]byte, error) {

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

// ExtractValidationInformation finds and parses the Validation Information embedded in the PDF document
func ExtractValidationInformation(path string) ([]*ocsp.Response, []*pkix.CertificateList, error) {

	context, err := pdfcpu.ReadContextFile(path)
	if err != nil {
		return nil, nil, err
	}
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

	ocsps := make([]*ocsp.Response, len(ocspsarray))

	// Iterate through the ocsp list
	for i, ocsparrayelement := range ocspsarray {

		// Each element on the array is an indirect object pointing to the OCSP stream dictionary
		arrayElement := ocsparrayelement.(pdf.IndirectRef)

		ocspbyte, err := pdf.ExtractStreamData(context, arrayElement.ObjectNumber.Value())
		if err != nil {
			return nil, nil, err
		}

		// Each OCSP object is an ASN.1 encoded OCSP response

		// fmt.Println(hex.EncodeToString(ocspstream))
		// Parse OCSP response
		ocspresponse, err := ocsp.ParseResponse(ocspbyte, nil)
		if err != nil {
			return nil, nil, err
		}

		// Add ocsp to return ocsp array
		ocsps[i] = ocspresponse
	}

	// Access CRLs object
	crlsobj, found := dssdict.Find("CRLs")
	if !found {
		return nil, nil, errors.New("crl object not found in dss dictionary")
	}

	crlsarray, err := context.DereferenceArray(crlsobj)
	if err != nil {
		return nil, nil, err
	}

	crls := make([]*pkix.CertificateList, len(crlsarray))

	// Iterate throw the CRLs on the array and access stream dictionary
	for i, crlarrayelement := range crlsarray {

		// The element on the array is an indirect object pointing to the CRL stream dictionary
		arrayElement := crlarrayelement.(pdf.IndirectRef)

		crlstream, err := pdf.ExtractStreamData(context, arrayElement.ObjectNumber.Value())
		if err != nil {
			return nil, nil, err
		}

		certList, err := x509.ParseCRL(crlstream)
		if err != nil {
			return ocsps, nil, err
		}
		// Include CRL in return CRL array
		crls[i] = certList
	}
	return ocsps, crls, nil
}
