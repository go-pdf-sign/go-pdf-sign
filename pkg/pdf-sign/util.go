package pdf_sign

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"reflect"

	"crypto/x509"

	pdf "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"go.mozilla.org/pkcs7"
)

func WriteOutPdf(c *pdf.Context, w io.Writer) error {
	fmt.Println(c.XRefTable.HeaderVersion)
	c.ResetWriteContext()
	c.Write.Eol = "\n"
	c.Write.Writer = bufio.NewWriter(w)
	return pdf.Write(c)
}

func GetHashRanges(c *pdf.Context, sig *pdf.Dict) [][]byte {
	w := bytes.NewBuffer(nil)
	WriteOutPdf(c, w)
	b := w.Bytes()
	ranges := make([][]byte, 0)
	// these are fake ranges
	ranges = append(ranges, b[0:100])
	ranges = append(ranges, b[200:300])
	return ranges
}

type PaddedObject struct {
	Object pdf.Object
	Size   int
}

func NewPaddedObject(o pdf.Array, size int) PaddedObject {
	a := PaddedObject{Object: o}
	a.Size = size
	return a
}

func pad(len int) string {
	s := ""
	for i := 0; i < len; i++ {
		s = s + " "
	}
	return s
}

/* this does not work because pdfcpu expects specific types */
func (p PaddedObject) PDFString() string {
	s := p.Object.PDFString()
	if len(s) > p.Size {
		panic("PaddedObject: object does not fit")
	}
	return s + pad(p.Size-len(s))
}

func (p PaddedObject) String() string {
	return p.Object.String()
}

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
