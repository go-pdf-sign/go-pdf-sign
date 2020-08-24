package pdf_sign

import (
	"encoding/pem"
	"fmt"
	"os"
	"reflect"

	"crypto/x509"

	"go.mozilla.org/pkcs7"
)

func Sign(hash []byte) []byte {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		fmt.Printf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := pkcs7.NewSignedData(hash)
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
	}

	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	// Add the signing cert and private key
	fmt.Println(reflect.TypeOf(*cert.PrivateKey))
	if err := signedData.AddSigner(cert.Certificate, *cert.PrivateKey, pkcs7.SignerInfoConfig{}); err != nil {
		fmt.Printf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
	return detachedSignature
}
