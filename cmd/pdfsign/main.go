package main

import (
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	pdf "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"

	rfc3161 "github.com/clocklock/go-rfc3161"
	pdfsign "github.com/go-pdf-sign/go-pdf-sign/pkg/pdf-sign"
	PDFCPULog "github.com/pdfcpu/pdfcpu/pkg/log"
)

type DummySigner struct {
	pdf.Signer
}

func (d DummySigner) EstimateSignatureLength() int {
	return 100
}

func (d DummySigner) Sign(r io.Reader) ([]byte, error) {
	h := sha256.New()
	_, err := io.Copy(h, r)
	if err != nil {
		return nil, err
	}
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	return []byte{1, 2, 3, 4, 5}, nil
}

type Pkcs7Signer struct {
	pdf.Signer
}

func (s Pkcs7Signer) EstimateSignatureLength() int {
	return 10000
}

func (s Pkcs7Signer) Sign(r io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return pdfsign.Sign(b)
}

type TsaSigner struct {
	pdf.Signer
	Url string
}

func (s TsaSigner) EstimateSignatureLength() int {
	return 10000
}

func (s TsaSigner) Sign(r io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)
	tsa := rfc3161.NewClient(s.Url)
	tsq, err := rfc3161.NewTimeStampReq(crypto.SHA256, digest[:])
	tsq.CertReq = true
	if err != nil {
		return nil, err
	}
	//fmt.Println(tsq)
	//fmt.Println(tsa)
	tsr, err := tsa.Do(tsq)
	if err != nil {
		return nil, err
	}
	// Marshal the Signed Attributes
	sig, err := asn1.Marshal(tsr.TimeStampToken)
	if err != nil {
		return nil, err
	}
	fmt.Println(tsr.Status)
	fmt.Println(tsr.TimeStampToken)
	fmt.Println(hex.EncodeToString(sig))
	return sig, nil
}

func doSign() error {
	// Create a signed version of inFile.

	if len(os.Args) != 3 {
		panic("usage: xxx test.pdf out.pdf")
	}
	inFile := os.Args[1]
	outFile := os.Args[2]
	fmt.Println(inFile, outFile)
	signer := Pkcs7Signer{}
	//signer := TsaSigner{Url: "https://freetsa.org/tsr"}
	err := pdfcpu.TimestampFile(inFile, outFile, nil, signer)
	if err == pdf.ErrHasAcroForm {
		log.Println("already has an AcroForm")
		return err
	}
	return err
}

func main() {
	PDFCPULog.SetDefaultCLILogger()
	//PDFCPULog.SetDefaultTraceLogger()
	//PDFCPULog.SetDefaultParseLogger()
	//PDFCPULog.SetDefaultReadLogger()
	PDFCPULog.SetDefaultValidateLogger()
	PDFCPULog.SetDefaultOptimizeLogger()
	//PDFCPULog.SetDefaultWriteLogger()

	err := doSign()
	if err != nil {
		panic(err)
	}
}
