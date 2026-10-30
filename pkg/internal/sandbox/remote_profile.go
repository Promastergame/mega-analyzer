package sandbox

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type remoteProfile struct {
	Endpoint    string   `json:"endpoint"`
	Certificate string   `json:"certificate"`
	Token       string   `json:"token"`
	Python      string   `json:"python"`
	Args        []string `json:"args"`
}

func validateRemoteEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("remote endpoint must be a private numeric guest IP:port")
	}
	ip, err := netip.ParseAddr(host)
	p, e := strconv.Atoi(port)
	if err != nil || e != nil || p < 1 || p > 65535 || !ip.IsPrivate() || ip.Zone() != "" || ip.IsLoopback() || ip.Is4In6() {
		return fmt.Errorf("remote endpoint must be a private numeric guest IP:port")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("cannot exclude local interfaces: %w", err)
	}
	for _, a := range addresses {
		if prefix, e := netip.ParsePrefix(a.String()); e == nil && prefix.Addr().Unmap() == ip.Unmap() {
			return fmt.Errorf("remote endpoint points to this host; use the VM guest IP")
		}
	}
	return nil
}

func validateGuestTarget(target string) error {
	if len(target) < 7 || len(target) > 4096 || !((target[0] >= 'A' && target[0] <= 'Z') || (target[0] >= 'a' && target[0] <= 'z')) || target[1:3] != ":\\" || !strings.HasSuffix(strings.ToLower(target), ".exe") || strings.ContainsAny(target[3:], ":\x00\r\n") {
		return fmt.Errorf("remote target must be an absolute guest drive path to an .exe, e.g. C:\\Lab\\sample.exe")
	}
	return nil
}

func loadRemoteProfile(path string) (remoteProfile, error) {
	var p remoteProfile
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil {
		return p, err
	}
	if len(b) > 32768 {
		return p, fmt.Errorf("remote profile too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return p, fmt.Errorf("invalid remote profile JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return p, fmt.Errorf("trailing remote profile JSON")
	}
	if err = validateRemoteEndpoint(p.Endpoint); err != nil {
		return p, err
	}
	token, err := hex.DecodeString(p.Token)
	if err != nil || len(token) != 32 {
		return p, fmt.Errorf("profile token must be 32 random bytes encoded as hex")
	}
	if len(p.Args) > 64 {
		return p, fmt.Errorf("too many guest arguments")
	}
	for _, arg := range p.Args {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return p, fmt.Errorf("invalid guest argument")
		}
	}
	if p.Python == "" || !filepath.IsAbs(p.Python) {
		return p, fmt.Errorf("profile python must be an absolute path to the trusted host interpreter")
	}
	if info, e := os.Stat(p.Python); e != nil || !info.Mode().IsRegular() {
		return p, fmt.Errorf("host Python interpreter not found")
	}
	if p.Certificate == "" {
		return p, fmt.Errorf("pinned TLS certificate required")
	}
	if !filepath.IsAbs(p.Certificate) {
		p.Certificate = filepath.Join(filepath.Dir(path), p.Certificate)
	}
	p.Certificate, err = filepath.Abs(p.Certificate)
	if err != nil {
		return p, err
	}
	fCert, err := os.Open(p.Certificate)
	if err != nil {
		return p, err
	}
	defer fCert.Close()
	certData, err := io.ReadAll(io.LimitReader(fCert, 16385))
	if err != nil {
		return p, err
	}
	block, rest := pem.Decode(certData)
	if len(certData) > 16384 || block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return p, fmt.Errorf("host pin must contain only one public certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return p, fmt.Errorf("invalid pinned TLS certificate")
	}
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return p, fmt.Errorf("pinned TLS certificate is not currently valid")
	}
	return p, nil
}

// CreateRemoteProfile writes a new provisioning directory; existing files are
// never replaced. Only guest/ is copied into the clean VM before snapshotting.
func CreateRemoteProfile(dir, endpoint, python string) (string, error) {
	if err := validateRemoteEndpoint(endpoint); err != nil {
		return "", err
	}
	if !filepath.IsAbs(python) {
		return "", fmt.Errorf("provide the absolute host Python path")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return "", fmt.Errorf("create NEW profile directory: %w", err)
	}
	if err = os.Mkdir(filepath.Join(dir, "guest"), 0700); err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	host, _, _ := net.SplitHostPort(endpoint)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Mega Analyzer VM Agent"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(host)}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	guestPEM := append(bytes.Clone(cert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return "", err
	}
	profile := remoteProfile{Endpoint: endpoint, Certificate: "server.pem", Token: hex.EncodeToString(token), Python: python, Args: []string{}}
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return "", err
	}
	// Endpoint and token have strict syntax; no user text is evaluated here.
	launcher := "param([Parameter(Mandatory=$true)][string]$Agent)\r\n$ErrorActionPreference = 'Stop'\r\n" +
		"# Run INSIDE the disposable Windows VM, using a matching frida-server.exe.\r\n" +
		"& $Agent --listen '" + endpoint + "' --certificate (Join-Path $PSScriptRoot 'agent.pem') --token '" + profile.Token + "'\r\nexit $LASTEXITCODE\r\n"
	files := []struct {
		name string
		data []byte
	}{{"server.pem", cert}, {"host.json", data}, {filepath.Join("guest", "agent.pem"), guestPEM}, {filepath.Join("guest", "start-agent.ps1"), []byte(launcher)}}
	for _, entry := range files {
		f, e := os.OpenFile(filepath.Join(dir, entry.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return "", e
		}
		_, e = f.Write(entry.data)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return "", e
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return filepath.Join(dir, "host.json"), nil
}
