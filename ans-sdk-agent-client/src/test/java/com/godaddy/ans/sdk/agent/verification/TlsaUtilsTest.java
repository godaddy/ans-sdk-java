package com.godaddy.ans.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link TlsaUtils}.
 */
class TlsaUtilsTest {

    // ==================== Constants Tests ====================

    @Test
    @DisplayName("TLSA selector constants should have correct values")
    void tlsaSelectorConstantsShouldHaveCorrectValues() {
        assertThat(TlsaUtils.SELECTOR_FULL_CERT).isEqualTo(0);
        assertThat(TlsaUtils.SELECTOR_SPKI).isEqualTo(1);
    }

    @Test
    @DisplayName("TLSA matching type constants should have correct values")
    void tlsaMatchingTypeConstantsShouldHaveCorrectValues() {
        assertThat(TlsaUtils.MATCH_EXACT).isEqualTo(0);
        assertThat(TlsaUtils.MATCH_SHA256).isEqualTo(1);
        assertThat(TlsaUtils.MATCH_SHA512).isEqualTo(2);
    }

    // ==================== describeMatchType Tests ====================

    @Test
    @DisplayName("describeMatchType should describe SPKI-SHA-256")
    void describeMatchTypeShouldDescribeSpkiSha256() {
        String result = TlsaUtils.describeMatchType(TlsaUtils.SELECTOR_SPKI, TlsaUtils.MATCH_SHA256);
        assertThat(result).isEqualTo("SPKI-SHA-256");
    }

    @Test
    @DisplayName("describeMatchType should describe FullCert-SHA-256")
    void describeMatchTypeShouldDescribeFullCertSha256() {
        String result = TlsaUtils.describeMatchType(TlsaUtils.SELECTOR_FULL_CERT, TlsaUtils.MATCH_SHA256);
        assertThat(result).isEqualTo("FullCert-SHA-256");
    }

    @Test
    @DisplayName("describeMatchType should describe SPKI-SHA-512")
    void describeMatchTypeShouldDescribeSpkiSha512() {
        String result = TlsaUtils.describeMatchType(TlsaUtils.SELECTOR_SPKI, TlsaUtils.MATCH_SHA512);
        assertThat(result).isEqualTo("SPKI-SHA-512");
    }

    @Test
    @DisplayName("describeMatchType should describe FullCert-Exact")
    void describeMatchTypeShouldDescribeFullCertExact() {
        String result = TlsaUtils.describeMatchType(TlsaUtils.SELECTOR_FULL_CERT, TlsaUtils.MATCH_EXACT);
        assertThat(result).isEqualTo("FullCert-Exact");
    }

    // ==================== bytesToHex Tests ====================

    @Test
    @DisplayName("bytesToHex should convert bytes to lowercase hex")
    void bytesToHexShouldConvertBytesToLowercaseHex() {
        byte[] bytes = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
        String result = TlsaUtils.bytesToHex(bytes);
        assertThat(result).isEqualTo("deadbeef");
    }

    @Test
    @DisplayName("bytesToHex should handle empty array")
    void bytesToHexShouldHandleEmptyArray() {
        byte[] bytes = {};
        String result = TlsaUtils.bytesToHex(bytes);
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("bytesToHex should handle null")
    void bytesToHexShouldHandleNull() {
        String result = TlsaUtils.bytesToHex(null);
        assertThat(result).isEqualTo("null");
    }

    @Test
    @DisplayName("bytesToHex should pad single digits with leading zero")
    void bytesToHexShouldPadSingleDigitsWithLeadingZero() {
        byte[] bytes = {0x00, 0x01, 0x0F};
        String result = TlsaUtils.bytesToHex(bytes);
        assertThat(result).isEqualTo("00010f");
    }

    // ==================== computeCertificateData Tests ====================

    @Test
    @DisplayName("computeCertificateData should return null for unknown selector")
    void computeCertificateDataShouldReturnNullForUnknownSelector() throws Exception {
        X509Certificate cert = createSelfSignedCertificate();
        byte[] result = TlsaUtils.computeCertificateData(cert, 99, TlsaUtils.MATCH_SHA256);
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("computeCertificateData should return null for unknown matching type")
    void computeCertificateDataShouldReturnNullForUnknownMatchingType() throws Exception {
        X509Certificate cert = createSelfSignedCertificate();
        byte[] result = TlsaUtils.computeCertificateData(cert, TlsaUtils.SELECTOR_SPKI, 99);
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("computeCertificateData with SPKI-SHA256 should return 32 bytes")
    void computeCertificateDataWithSpkiSha256ShouldReturn32Bytes() throws Exception {
        X509Certificate cert = createSelfSignedCertificate();
        byte[] result = TlsaUtils.computeCertificateData(cert, TlsaUtils.SELECTOR_SPKI, TlsaUtils.MATCH_SHA256);
        assertThat(result).hasSize(32); // SHA-256 produces 32 bytes
    }

    @Test
    @DisplayName("computeCertificateData with SPKI-SHA512 should return 64 bytes")
    void computeCertificateDataWithSpkiSha512ShouldReturn64Bytes() throws Exception {
        X509Certificate cert = createSelfSignedCertificate();
        byte[] result = TlsaUtils.computeCertificateData(cert, TlsaUtils.SELECTOR_SPKI, TlsaUtils.MATCH_SHA512);
        assertThat(result).hasSize(64); // SHA-512 produces 64 bytes
    }

    @Test
    @DisplayName("computeCertificateData with SPKI-Exact should return raw SPKI")
    void computeCertificateDataWithSpkiExactShouldReturnRawSpki() throws Exception {
        X509Certificate cert = createSelfSignedCertificate();
        byte[] result = TlsaUtils.computeCertificateData(cert, TlsaUtils.SELECTOR_SPKI, TlsaUtils.MATCH_EXACT);
        byte[] expectedSpki = cert.getPublicKey().getEncoded();
        assertThat(result).isEqualTo(expectedSpki);
    }

    @Test
    @DisplayName("computeCertificateData with FullCert-SHA256 should return 32 bytes")
    void computeCertificateDataWithFullCertSha256ShouldReturn32Bytes() throws Exception {
        X509Certificate cert = createSelfSignedCertificate();
        byte[] result = TlsaUtils.computeCertificateData(cert, TlsaUtils.SELECTOR_FULL_CERT, TlsaUtils.MATCH_SHA256);
        assertThat(result).hasSize(32);
    }

    @Test
    @DisplayName("computeCertificateData should be deterministic")
    void computeCertificateDataShouldBeDeterministic() throws Exception {
        X509Certificate cert = createSelfSignedCertificate();
        byte[] result1 = TlsaUtils.computeCertificateData(cert, TlsaUtils.SELECTOR_SPKI, TlsaUtils.MATCH_SHA256);
        byte[] result2 = TlsaUtils.computeCertificateData(cert, TlsaUtils.SELECTOR_SPKI, TlsaUtils.MATCH_SHA256);
        assertThat(result1).isEqualTo(result2);
    }

    // ==================== Helper Methods ====================

    /**
     * Creates a self-signed certificate for testing.
     */
    private X509Certificate createSelfSignedCertificate() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Use BouncyCastle to create a self-signed certificate
        org.bouncycastle.asn1.x500.X500Name issuer = new org.bouncycastle.asn1.x500.X500Name("CN=Test");
        java.math.BigInteger serial = java.math.BigInteger.valueOf(System.currentTimeMillis());
        java.util.Date notBefore = new java.util.Date();
        java.util.Date notAfter = new java.util.Date(System.currentTimeMillis() + 86400000L);

        org.bouncycastle.cert.X509v3CertificateBuilder certBuilder =
            new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());

        org.bouncycastle.operator.ContentSigner signer =
            new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA")
                .build(keyPair.getPrivate());

        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
            .getCertificate(certBuilder.build(signer));
    }
}