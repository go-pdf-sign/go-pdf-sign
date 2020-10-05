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

Further reading:

https://github.com/go-pdf-sign/go-pdf-sign
https://github.com/go-pdf-sign/go-pdf-sign/wiki/Parsing-a-signed-PDF
