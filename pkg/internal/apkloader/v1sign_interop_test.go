package apkloader

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"testing"
)

func TestPKCS7UsesUniversalSetForSignedAttributes(t *testing.T) {
	key, cert, err := generateDebugCertificate()
	if err != nil {
		t.Fatal(err)
	}
	sf := []byte("Signature-Version: 1.0\r\nCreated-By: CMS interoperability test\r\n\r\n")
	block, err := buildPKCS7SignatureBlock(sf, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	// Decode with the standard ASN.1 library, independently of the signer.
	var envelope struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	if _, err := asn1.Unmarshal(block, &envelope); err != nil {
		t.Fatal(err)
	}
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}
	if _, err := asn1.Unmarshal(envelope.Content.Bytes, &signedData); err != nil {
		t.Fatal(err)
	}
	var signer struct {
		Version            int
		IssuerAndSerial    asn1.RawValue
		DigestAlgorithm    asn1.RawValue
		SignedAttributes   asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		Signature          []byte
	}
	if _, err := asn1.Unmarshal(signedData.SignerInfos.Bytes, &signer); err != nil {
		t.Fatal(err)
	}
	if signer.SignedAttributes.Class != asn1.ClassContextSpecific || signer.SignedAttributes.Tag != 0 {
		t.Fatal("SignerInfo must encode signedAttrs with the implicit [0] tag")
	}
	// RFC 5652 section 5.4: the signature covers DER SET OF, not that [0] tag.
	attrsDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: signer.SignedAttributes.Bytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(attrsDER)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signer.Signature); err != nil {
		t.Fatalf("signature is not valid CMS SignedData: %v", err)
	}
	if _, err := verifyPKCS7SignatureBlock(block, sf); err != nil {
		t.Fatalf("offline verifier rejected the standard signature: %v", err)
	}

	// The previous signer and verifier agreed on a nonstandard [0] hash.
	// Keep that invalid encoding rejected even though its RSA math is valid.
	legacyDigest := sha256.Sum256(signer.SignedAttributes.FullBytes)
	legacySignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, legacyDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(block, signer.Signature) != 1 {
		t.Fatal("ambiguous signature location in fixture")
	}
	legacy := bytes.Replace(block, signer.Signature, legacySignature, 1)
	if _, err := verifyPKCS7SignatureBlock(legacy, sf); err == nil {
		t.Fatal("offline verifier accepted the nonstandard implicit-tag signature")
	}
}
