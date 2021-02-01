package internal

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	validFor                   = 365 * 24 * time.Hour
	certFileFlags  int         = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	certMode       os.FileMode = 0666
	serverKeyFlags int         = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	serverKeyMode  os.FileMode = 0600
)

// Err* constants are found in our returned CertError under err.Type, so you can
// cast and check if it's a certain type of error.
const (
	ErrParseCert    = "could not be parsed"
	ErrExpiredCert  = "is expired"
	ErrCreateCert   = "could not be created"
	ErrExistsCert   = "already exists"
	ErrEncodeCert   = "could not encode"
	ErrNotFoundCert = "cert could not be found"
)

// CertError records a certificate-related error.
type CertError struct {
	Type string // ErrParseCert or ErrExpiredCert
	Path string // path to the certificate file
	Err  error  // In the case of ErrParseCert, the parsing error
}

func (e CertError) Error() string {
	msg := e.Path + " " + e.Type
	if e.Err != nil {
		msg += " [" + e.Err.Error() + "]"
	}

	return msg
}

type NumberError struct {
	Err error
}

func (n *NumberError) Error() string {
	return fmt.Sprintf("failed to generate serial number: %s", n.Err)
}

// GenerateCerts creates a CA certificate which is used to sign a created server
// certificate which will have a corresponding key, all saved as PEM files. An
// error is generated if any of the files already exist.
//
// randReader := crand.Reader to be declared in calling function.
func GenerateCerts(caFile, serverPemFile, serverKeyFile, domain string,
	bitsForRootRSAKey int, bitsForServerRSAKey int, randReader io.Reader, fileFlags int) error {
	err := checkIfCertsExist([]string{caFile, serverPemFile, serverKeyFile})
	if err != nil {
		return err
	}

	// generate RSA keys for root
	rootKey, err := rsa.GenerateKey(crand.Reader, bitsForRootRSAKey)
	if err != nil {
		return err
	}

	// generate RSA keys for server
	serverKey, err := rsa.GenerateKey(crand.Reader, bitsForServerRSAKey)
	if err != nil {
		return err
	}

	// generate root CA
	err = generateCertificates(caFile, domain, rootKey, serverKey, serverPemFile, randReader, fileFlags)
	if err != nil {
		return err
	}

	// store the server's key
	pemBlock := &pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}
	err = encodeAndSavePEM(pemBlock, serverKeyFile, serverKeyFlags, serverKeyMode)

	return err
}

// checkIfCertsExist checks if any of the files exist, if yes then returns
// error.
func checkIfCertsExist(certFiles []string) error {
	for _, cFile := range certFiles {
		if _, err := os.Stat(cFile); err == nil {
			return &CertError{Type: ErrExistsCert, Path: cFile, Err: err}
		}
	}

	return nil
}

// Generate root and server certificate.
func generateCertificates(caFile, domain string, rootKey *rsa.PrivateKey, serverKey *rsa.PrivateKey,
	serverPemFile string, randReader io.Reader, fileFlags int) error {
	// create templates for root and server certificates.
	// rootCertTemplate   : rootServerTemplates[0]
	// serverCertTemplate : rootServerTemplates[1]
	rootServerTemplates := make([]*x509.Certificate, 2)
	for i := 0; i < len(rootServerTemplates); i++ {
		certTmplt, err := certTemplate(domain, randReader)
		if err != nil {
			return err
		}

		rootServerTemplates[i] = certTmplt
	}

	rootServerTemplates[0].IsCA = true
	rootServerTemplates[0].KeyUsage |= x509.KeyUsageCertSign

	rootCert, err := generateRootCert(caFile, rootServerTemplates[0], rootKey, randReader, fileFlags)
	if err != nil {
		return err
	}

	// generate server cert, signed by root CA
	err = generateServerCert(serverPemFile, rootCert, rootServerTemplates[1], rootKey, serverKey,
		randReader, fileFlags)

	return err
}

// certTemplate creates a certificate template with a random serial number,
// valid from now until validFor. It will be valid for supplied domain.
func certTemplate(domain string, randReader io.Reader) (*x509.Certificate, error) {
	serialNumLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := crand.Int(randReader, serialNumLimit)
	if err != nil {
		return nil, &NumberError{Err: err}
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"wr manager"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validFor),
		IPAddresses:           []net.IP{net.ParseIP("0.0.0.0"), net.ParseIP("127.0.0.1")},
		DNSNames:              []string{domain},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return &template, nil
}

// generateRootCert generates and returns root certificate.
func generateRootCert(caFile string, template *x509.Certificate, rootKey *rsa.PrivateKey,
	randReader io.Reader, fileFlags int) (*x509.Certificate, error) {
	// generate root certificate
	rootCertByte, err := createCertFromTemplate(template, template, &rootKey.PublicKey, rootKey, randReader)
	if err != nil {
		return nil, err
	}

	rootCert, err := parseCertAndSavePEM(rootCertByte, caFile, fileFlags)
	if err != nil {
		return nil, err
	}

	return rootCert, err
}

// createCertFromTemplate creates a certificate given a template, siginign it
// against its parent. Returned in DER encoding.
func createCertFromTemplate(template, parentCert *x509.Certificate, pubKey interface{},
	parentPvtKey interface{}, randReader io.Reader) ([]byte, error) {
	certDER, err := x509.CreateCertificate(randReader, template, parentCert, pubKey, parentPvtKey)
	if err != nil {
		return nil, CertError{Type: ErrCreateCert, Err: err}
	}

	return certDER, nil
}

// parseCertAndSavePEM parses the certificate to reuse it and saves it in PEM
// format to certPath.
func parseCertAndSavePEM(certByte []byte, certPath string, flags int) (*x509.Certificate, error) {
	// parse the resulting certificate so we can use it again
	cert, err := x509.ParseCertificate(certByte)
	if err != nil {
		return nil, CertError{Type: ErrParseCert, Path: certPath, Err: err}
	}

	block := &pem.Block{Type: "CERTIFICATE", Bytes: certByte}

	err = encodeAndSavePEM(block, certPath, flags, certMode)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func encodeAndSavePEM(block *pem.Block, certPath string, flags int, mode os.FileMode) error {
	certOut, err := os.OpenFile(certPath, flags, mode)
	if err != nil {
		return CertError{Type: ErrCreateCert, Path: certPath, Err: err}
	}

	err = pem.Encode(certOut, block)
	if err != nil {
		return CertError{Type: ErrEncodeCert, Path: certPath, Err: err}
	}

	err = certOut.Close()

	return err
}

// generateServerCert generates and returns server certificate signed by root
// CA.
func generateServerCert(serverPemFile string, rootCert *x509.Certificate, template *x509.Certificate,
	rootKey *rsa.PrivateKey, serverKey *rsa.PrivateKey, randReader io.Reader, fileFlags int) error {
	// generate server cert
	servCertBtye, err := createCertFromTemplate(template, rootCert, &serverKey.PublicKey, rootKey, randReader)
	if err != nil {
		return err
	}

	_, err = parseCertAndSavePEM(servCertBtye, serverPemFile, fileFlags)
	if err != nil {
		return err
	}

	return err
}

// CheckCerts checks if the given cert and key file are readable. If one or
// both of them are not, returns an error.
func CheckCerts(serverPemFile string, serverKeyFile string) error {
	if _, err := os.Stat(serverPemFile); err != nil {
		return err
	} else if _, err := os.Stat(serverKeyFile); err != nil {
		return err
	}

	return nil
}

// CertExpiry returns the time that the certificate given by the path to a pem
// file will expire.
func CertExpiry(certFile string) (time.Time, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return time.Now(), err
	}

	cert := findPEMBlockAndReturnCert(certPEMBlock)
	if len(cert.Certificate) == 0 {
		return time.Now(), CertError{Type: ErrNotFoundCert, Path: certFile}
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Now(), CertError{Type: ErrParseCert, Path: certFile, Err: err}
	}

	return x509Cert.NotAfter, nil
}

// findPEMBlockAndReturnCert finds the next PEM formatted block in the input
// and then returns a tls certificate.
func findPEMBlockAndReturnCert(certPEMBlock []byte) tls.Certificate {
	var cert tls.Certificate

	for {
		var certDERBlock *pem.Block

		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	return cert
}
