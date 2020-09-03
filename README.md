# go-pdf-sign

_WORK IN PROGRESS_

_Golang PDF signing and validation tools_

## Signed PDF Validation

Usage:
```
go run cmd/pdfvalidate/main.go mysignedpdf.pdf mytrustedanchors.pem
```

The second argument is optional. It points to a file containing a sequence of trusted CA certificates in pem format.

The program __verify.go__:

 - parses and extracts the content and signature information from a signed pdf
 - parses and extracts the timestamp from the pkcs7 signature
 - parses and extracts the revocation information from the pkcs7 signature
 - parses and extracts the validation information from the signed pdf
 - verifies the timestamp and validates it against the validation information
 - verifies the signature and validates it against the revocation information
 - it also works with only timestamped documents

Limitations:
 - it does not work with documents which were signed several times 
 - it does not work with password-protected documents


## PDF Signature 

A PDF is a ascii file which can include some binary content. The information in a PDF is structured as a tree of objects, which can be:

* Boolean
* Numbers
* Strings - enclosed with parenthesees (...)
* Names - starting with a slash /
* Arrays - ordered collections of objects - enclosed with square brackets [...]
* Dictionaries - collections of objects indexed by Names enclosed with pointy double brackets <...>
* Streams - large amounts of (usually compressed) binary data enclosed between "stream" and "endstream"
* Null 

A PDF can be signed i.e. it can contain a (visible or not-visible) electronic signature. A signed PDF includes a signature object embedded in the document. According to the PADES standard:

* The signature is included in a data structure in the PDF itself called the __Signature Dictionary__
* The signature value is encoded as a binary object using CMS

The PDF Signature binary value is placed into the __Contents__ entry of the signature dictionary

To better understand how this works, let's take a look at the internal structure of a PDF document:
```
vi mysignedpdf.pdf
```
### xRef Table

At the end of the file, we find the __Cross-Reference Table__ (xRefTable). It contains and allows random access to all the objects in the document. Each object is represented by one entry in the cross reference table, which is always 20 bytes long: 
```
xref
0 1
0000000000 65535 f
7 1
0000077641 00000 n
18 10
0000077977 00000 n
0000074102 00000 n
0000075518 00000 n
0000077371 00000 n
0000077396 00000 n
0000077421 00000 n
0000077465 00000 n
0000077534 00000 n
0000077559 00000 n
0000077584 00000 n
```

The subsections are marked by the lines containing only two numbers. The first number is the object number and the second one is the number of elements on the subsection. So we see we have three subsections with numbers 0, 7 and 18 with respectively 1, 1 and 10 elements inside.

Each object is represented by one entry which is 20 bytes long. For example, we take the first object on subsection number 18:
```
0000077977 00000 n
```

* The first 10 bytes are the offset from beginning of the document to the begin of the object
* The numbers following the first space represent the object generation number
* A letter at the end indicates if the object is free (f) or in use (n)

### Trailer
The PDF Trailer specifies how to find the xref table and other special objects.

```
trailer
<<
/Size 28
/Root 18 0 R
/Info 7 0 R
/ID [<f7d77b3d22b9f92829d49ff5d78b8f28><73c275ca4e477e89d65905c860df23b7>]
/Prev 73557
>>
```

The __Document Catalog__ is the root of the objects in the PDF document and it's specified by the __/Root__ element in the __Trailer__ section. We see the Root Dictionary is the object number 18. There is additional information in object number 7.

The Root element is an indirect object. Objects in a PDF can be __indirect__. An indirect object is a numbered object represented with keywords __obj__ and __endobj__. The 18 is the Object ID and the 0 is the generation number. The letter R indicates that this is a reference to another object.

We find the referenced object:
```
18 0 obj
<<
/Type
/Catalog
/Pages 8 0 R
/Outlines 16 0 R
/AcroForm 
	<<
	/Fields[3 0 R]
	...
	/SigFlags 
	3
	>>
>>
endobj
```
The Root dictionary contains an object named __AcroForm__ whose value is also a dictionary. One of the objects in the AcroForm dictionary is an indirect object named __Fields__, which references object number 3.

```
3 0 obj
<<
/FT
/Sig
/T(Signature1)
/V 1 0 R
/F 132
/Type
/Annot
/Subtype
/Widget
/Rect[0 0 0 0]
/AP
	<<
	/N 2 0 R
	>>
/P 4 0 R
/DR<<>>>>
endobj
```

An object named __V__ is again an indirect object whose value references to object number 1. The Type of the object is __Sig__, so it looks like we just found the __Signature Dictionary__, which is supposed to contain the PDF signature.

```
<<
/Type
/Sig
/Filter
/Adobe.PPKLite
/SubFilter
/adbe.pkcs7.detached
/Reason()
/Location()
/ContactInfo()
/M(D:20200428104559+02'00')
/ByteRange [0 372 60374 13727 ]                                                            
/Contents 
<30823d ... >
```
The Filter value is __Adobe.PPKLite__ and the Subfilter value is __adbe.pkcs7.detached__.

The __Contents__ object contains the signature encoded as a CMS binary object.

### ByteRange

For the CMS signature, a digest is computed over a range of bytes of the file. For a PDF, this range includes the whole document excluding the signature itself, which is part of the document. The range is indicated by the __ByteRange__ entry in the __SignatureDictionary__.


## Long-Term Validation

_Validation Data_: Data necessary to validate an electronic signature: CA Certificate(s), OCSP, CRL

A LTV signature is valid after the signing certificate is expired, even after the Validation Data is not available online anymre. 

### DocumentSecurityStore (DSS)

According to the PADES regulation for the LTV Profile, the Document Security Store (DSS) contains information appended to a PDF document relating to its security including Validation-Related Information (VRI) and indirect references to the values of validation data for all signatures.

The "18 0 obj" (Root Dictionary / Catalog) is present twice in the document: once without DSS and once with it. Probably the explanation is that there are different revisions, since a new revision is needed to add to the document the Validation Data (DSS Dictionary). 
```
18 0 obj
<<
/Type
/Catalog
/Pages 8 0 R
/Outlines 16 0 R
/AcroForm
	<<
	/Fields[3 0 R]
	/DA(/Helv 0 Tf 0 g )
	/DR <</Font<</Helv 5 0 R/ZaDb 6 0 R>>>>
	/SigFlags 3
	>>
/DSS 27 0 R
/Version
/1.4
/Extensions
<</ESIC<</BaseVersion/1.7/ExtensionLevel 5>>>>>>
endobj
```

In the Root Dictionary (Catalog), we see an object named DSS with a reference to object number 27:
```
/DSS 27 0 R
```

Object 27 looks like it contains the Revocation Information, with references to the objects 24, 25 and 26.
```
27 0 obj
<<
/VRI 24 0 R
/OCSPs 25 0 R
/CRLs 26 0 R>>
endobj
```

Object 24 is the ValidationRelatedInformation (VRI) and references object 23:
```
24 0 obj
<</BF6636B968029A848497A37600BF53348E36A016 23 0 R>>
endobj
```

Object 23 contains references to the objects 21 and 22:
```
23 0 obj
<<
/OCSP 21 0 R
/CRL 22 0 R
>>
endobj
```

Object 21 is an array containing a single element, which is a reference to object 20, and which according to its name should point to the OCSP:
```
21 0 obj
[20 0 R]
endobj
```

Object 20 is dictionary containing a binary data stream: the OCSP
```
20 0 obj
<<
/Length 1784
/Filter
/FlateDecode>>
stream
x<9c>­...
endstream
endobj
```

Object 22 is an array containing a single element, which is a reference to object 19, and which according to its name should point to the CRL:
```
22 0 obj
[19 0 R]
endobj
```

Object 19 is again a dictionary containing a binary data stream: the CRL
```
19 0 obj
<</Length 1347/Filter/FlateDecode>>stream
x<9c>3h...
endstream
endobj
```

Object 25 is an array containing a single element, which is a reference to object 20, which is again the OCSP:
```
25 0 obj
[20 0 R]
endobj
```

Object 26 is an array containing a single element, which is a reference to object 19, which is again the CRL:
```
26 0 obj
[19 0 R]
endobj
```

### References
https://en.wikipedia.org/wiki/PDF
https://en.wikipedia.org/wiki/PAdES
https://www.etsi.org/deliver/etsi_ts/102700_102799/10277801/01.01.01_60/ts_10277801v010101p.pdf
https://github.com/pdfcpu/pdfcpu
