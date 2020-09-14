package pdf_sign

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strings"
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

	//sigbytesstring := hex.EncodeToString(signatureBytes)
	//fmt.Println(" ****** Signature bytes string: ", sigbytesstring)

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

// ExtractTimestampBytes accesses the pkcs7 signature object and returns the bytes of the timestamp
func ExtractTimestampBytes(signature *pkcs7.PKCS7) ([]byte, error) {

	signers := signature.Signers

	// Only 1 signer allowed
	if len(signers) != 1 {
		return nil, errors.New("there must be only one signer on the pkcs7")
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

			timestampBytes := unauthAttr.Value.Bytes

			return timestampBytes, nil
		}
	}
	return nil, errors.New("no timestamp found in pkcs7")
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

// ExtractRevocationInfo extracts the RevocationInformation from the signature. It returns false if none was found.
func ExtractRevocationInfo(signature *pkcs7.PKCS7) (bool, RevocationInfo, error) {

	var revocationInfo RevocationInfo

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
					return false, revocationInfo, err
				}

				revocationInfo.Ocsps = make([]*ocsp.Response, len(ri.OCSP))
				if len(ri.OCSP) > 0 {
					ocspResponse, err := ocsp.ParseResponse(ri.OCSP[0].Bytes, nil)
					if err != nil {
						return false, revocationInfo, err
					}
					revocationInfo.Ocsps[0] = ocspResponse
				}

				revocationInfo.Crls = make([]*pkix.CertificateList, len(ri.CRL))
				if len(ri.CRL) > 0 {
					crl, err := x509.ParseCRL(ri.CRL[0].Bytes)
					if err != nil {
						return false, revocationInfo, err
					}
					revocationInfo.Crls[0] = crl
				}

				// Either the CRL or the OCSP might be empty, but not both of them
				if len(ri.OCSP) == 0 && len(ri.CRL) == 0 {
					return false, revocationInfo, errors.New("both ocsp array and crl array are empty on revocationInfoArchival attribute")
				}
				return true, revocationInfo, nil
			}
		}
		log.Println("parse: no revocationInfoArchival on pkcs7")
	}
	return false, revocationInfo, nil
}

// ExtractDss extracts the dss dictionary from the pdf context
func ExtractDss(context *pdf.Context) (pdf.Dict, error) {

	// Access the Root Dictionary
	rootdict := context.RootDict

	// Find DSS Dictionary inside Root Dictionary
	dssdictref, found := rootdict.Find("DSS")
	if !found {
		return nil, errors.New("dss dictionary not found")
	}

	// DSS object is an indirect object pointing to the DSS dictionary
	dssdict, err := context.DereferenceDict(dssdictref)
	if err != nil {
		return nil, err
	}
	//log.Println("parse: dss dictionary found in pdf")

	return dssdict, nil
}

// ExtractVri extracts the vri dictionary from the pdf context
func ExtractVri(context *pdf.Context) (pdf.Dict, error) {

	dssdict, err := ExtractDss(context)
	if err != nil {
		return nil, err
	}
	//log.Println("parse: vri dictionary found in dss")

	// Find VRI dictionary
	vridictref, found := dssdict.Find("VRI")
	if !found {
		return nil, errors.New("vri dictionary not found")
	}

	// VRI object is an indirect object pointing to the VRI dictionary
	vridict, err := context.DereferenceDict(vridictref)
	if err != nil {
		return nil, err
	}

	return vridict, nil
}

// ExtractValidationInformation finds and parses the Validation Information embedded in the PDF document
// If sigbytes is nil (no reference to an existing signature), it gets the ocsp and crl directly from the dss dictionary
// I'm assuming here the ocsps and crls element nested directly under dss are the ones related to the timestamp
func ExtractValidationInformation(context *pdf.Context, sigbytes []byte) (RevocationInfo, error) {

	var validationInfo RevocationInfo
	var dict pdf.Dict
	var err error

	// Key for ocsp/crl is different for the dss and vri dictionaries
	var ocspkey string
	var crlkey string
	var certkey string

	if sigbytes == nil {

		log.Println("parse: retrieving validation info for timestamp")

		// Extract dss dictionary (no signature provided)
		dict, err = ExtractDss(context)
		if err != nil {
			return validationInfo, err
		}

		log.Println("parse: dss dictionary found in pdf")

		certkey = "Certs"
		ocspkey = "OCSPs"
		crlkey = "CRLs"

	} else {

		// The index of the vri dictionary entry is the base-16-encoded (uppercase) SHA1 digest of the signature to which it applies
		hash := sha1.New()
		hash.Write(sigbytes)
		// hashBytes is encoded in base16
		hashBytes := hash.Sum(nil)
		base16str := strings.ToUpper(hex.EncodeToString(hashBytes))

		validationInfo.Base16cert = base16str

		log.Println("parse: retrieving revocation info for signature: ", base16str)

		// Extract vri dictionary associated to the provided signature bytes
		vridict, err := ExtractVri(context)
		if err != nil {
			return validationInfo, err
		}

		// The value is the Signature VRI dictionary which contains the validation-related information for that signature
		vrientry, err := vridict.Entry("VRI", base16str, true)
		if err != nil {
			return validationInfo, err
		}

		dict, err = context.DereferenceDict(vrientry)
		if err != nil {
			return validationInfo, err
		}

		log.Println("parse: vri dictionary found in pdf")

		certkey = "Cert"
		ocspkey = "OCSP"
		crlkey = "CRL"
	}

	// Find Certs object
	certsobj, found := dict.Find(certkey)
	if found {

		// Certs object is an indirect object pointing to an array
		certsarray, err := context.DereferenceArray(certsobj)
		if err != nil {
			return validationInfo, err
		}

		certsbytes := make([][]byte, len(certsarray))
		for i, certsarrayelement := range certsarray {

			arrayElement := certsarrayelement.(pdf.IndirectRef)

			certbyte, err := pdf.ExtractStreamData(context, arrayElement.ObjectNumber.Value())
			if err != nil {
				return validationInfo, err
			}
			certsbytes[i] = certbyte
		}

		// Create array of certificates
		certs := make([]*x509.Certificate, len(certsbytes))

		// Each certificate object is an ASN.1 encoded x509 certificate
		for i, certstream := range certsbytes {

			// Parse certificate
			// cert, err := ocsp.ParseResponse(certstream, nil)
			cert, err := x509.ParseCertificate(certstream)
			if err != nil {
				return validationInfo, err
			}
			// Include parsed ocsp in ocsp array
			certs[i] = cert
		}
		validationInfo.Certs = certs

	} else {
		log.Println("parse: there is no cert(s) object on dss/vri dictionary")
	}

	// Access OCSPs object
	ocspsobj, found := dict.Find(ocspkey)
	if found {

		// OCSPs object is an indirect object pointing to an array
		ocspsarray, err := context.DereferenceArray(ocspsobj)
		if err != nil {
			return validationInfo, err
		}

		ocspsbytes := make([][]byte, len(ocspsarray))

		// Iterate through the ocsp list
		for i, ocsparrayelement := range ocspsarray {

			// Each element on the array is an indirect object pointing to the OCSP stream dictionary
			arrayElement := ocsparrayelement.(pdf.IndirectRef)

			ocspbyte, err := pdf.ExtractStreamData(context, arrayElement.ObjectNumber.Value())
			if err != nil {
				return validationInfo, err
			}
			ocspsbytes[i] = ocspbyte
		}

		// Create array of ocsp responses
		ocsps := make([]*ocsp.Response, len(ocspsbytes))

		// Each OCSP object is an ASN.1 encoded OCSP response
		for i, ocspstream := range ocspsbytes {

			// Parse OCSP response
			ocspresponse, err := ocsp.ParseResponse(ocspstream, nil)
			if err != nil {
				return validationInfo, err
			}
			// Include parsed ocsp in ocsp array
			ocsps[i] = ocspresponse
		}
		validationInfo.Ocsps = ocsps
		//fmt.Println("LEN OF OCSPS (parse) is ", len(ocsps))

	} else {
		log.Println("parse: there is no ocsp(s) object on dss/vri dictionary")
	}

	// Access CRLs object
	crlsobj, found := dict.Find(crlkey)
	if found {

		crlsarray, err := context.DereferenceArray(crlsobj)
		if err != nil {
			return validationInfo, err
		}
		crlsbytes := make([][]byte, len(crlsarray))

		// Iterate throw the CRLs on the array and access stream dictionary
		for i, crlarrayelement := range crlsarray {

			// The element on the array is an indirect object pointing to the CRL stream dictionary
			arrayElement := crlarrayelement.(pdf.IndirectRef)

			crlstream, err := pdf.ExtractStreamData(context, arrayElement.ObjectNumber.Value())
			if err != nil {
				return validationInfo, err
			}
			crlsbytes[i] = crlstream

		}

		// Create array of crls
		crls := make([]*pkix.CertificateList, len(crlsbytes))

		for i, crlstream := range crlsbytes {
			certList, err := x509.ParseCRL(crlstream)
			if err != nil {
				return validationInfo, err
			}
			// Include parsed crl in crl array
			crls[i] = certList
		}

		validationInfo.Crls = crls

	} else {
		log.Println("parse: there is no crl(s) object on dss/vri dictionary")
	}
	return validationInfo, nil
}
