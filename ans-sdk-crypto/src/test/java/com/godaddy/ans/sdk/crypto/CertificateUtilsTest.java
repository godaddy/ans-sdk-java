package com.godaddy.ans.sdk.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Additional tests for CertificateUtils to improve coverage.
 */
class CertificateUtilsTest {

    private static X509Certificate validCertificate;
    private static X509Certificate expiredCertificate;
    private static String validPem;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Create a valid certificate
        validCertificate = createCertificate("test.example.com",
            new Date(System.currentTimeMillis() - 86400000L), // 1 day ago
            new Date(System.currentTimeMillis() + 86400000L * 365) // 1 year from now
        );

        // Create an expired certificate
        expiredCertificate = createCertificate("expired.example.com",
            new Date(System.currentTimeMillis() - 86400000L * 365), // 1 year ago
            new Date(System.currentTimeMillis() - 86400000L) // 1 day ago
        );

        // Convert valid cert to PEM
        validPem = CertificateUtils.toPem(validCertificate);
    }

    @Test
    @DisplayName("parseCertificate should parse valid PEM")
    void parseCertificateShouldParseValidPem() {
        X509Certificate parsed = CertificateUtils.parseCertificate(validPem);

        assertThat(parsed).isNotNull();
        assertThat(parsed.getSubjectX500Principal().getName())
            .contains("test.example.com");
    }

    @Test
    @DisplayName("parseCertificate should throw for null input")
    void parseCertificateShouldThrowForNullInput() {
        assertThatThrownBy(() -> CertificateUtils.parseCertificate(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("parseCertificate should throw for blank input")
    void parseCertificateShouldThrowForBlankInput() {
        assertThatThrownBy(() -> CertificateUtils.parseCertificate("  "))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("parseCertificate should throw for invalid PEM")
    void parseCertificateShouldThrowForInvalidPem() {
        assertThatThrownBy(() -> CertificateUtils.parseCertificate("not a valid pem"))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("parseCertificateChain should parse valid chain")
    void parseCertificateChainShouldParseValidChain() {
        // Create a chain with two certificates
        X509Certificate cert1 = createCertificate("cert1.example.com",
            new Date(System.currentTimeMillis() - 86400000L),
            new Date(System.currentTimeMillis() + 86400000L * 365));
        X509Certificate cert2 = createCertificate("cert2.example.com",
            new Date(System.currentTimeMillis() - 86400000L),
            new Date(System.currentTimeMillis() + 86400000L * 365));

        String chain = CertificateUtils.toPem(cert1) + CertificateUtils.toPem(cert2);

        List<X509Certificate> parsed = CertificateUtils.parseCertificateChain(chain);

        assertThat(parsed).hasSize(2);
    }

    @Test
    @DisplayName("parseCertificateChain should throw for null input")
    void parseCertificateChainShouldThrowForNullInput() {
        assertThatThrownBy(() -> CertificateUtils.parseCertificateChain(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("parseCertificateChain should throw for blank input")
    void parseCertificateChainShouldThrowForBlankInput() {
        assertThatThrownBy(() -> CertificateUtils.parseCertificateChain("  "))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("parseCertificateChain should throw for invalid PEM content")
    void parseCertificateChainShouldThrowForInvalidPemContent() {
        String invalidPem = "-----BEGIN CERTIFICATE-----\ninvalid base64 content!\n-----END CERTIFICATE-----";
        assertThatThrownBy(() -> CertificateUtils.parseCertificateChain(invalidPem))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("parseCertificateChain should throw for non-certificate PEM content")
    void parseCertificateChainShouldThrowForNonCertificatePemContent() {
        // Valid PEM structure but contains something other than a certificate
        String nonCertPem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg==\n-----END PUBLIC KEY-----";
        assertThatThrownBy(() -> CertificateUtils.parseCertificateChain(nonCertPem))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("toPem should convert certificate to PEM format")
    void toPemShouldConvertCertificateToPemFormat() {
        String pem = CertificateUtils.toPem(validCertificate);

        assertThat(pem).isNotNull();
        assertThat(pem).contains("-----BEGIN CERTIFICATE-----");
        assertThat(pem).contains("-----END CERTIFICATE-----");
    }

    @Test
    @DisplayName("toPem should throw for null certificate")
    void toPemShouldThrowForNullCertificate() {
        assertThatThrownBy(() -> CertificateUtils.toPem(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("isValid should return true for valid certificate")
    void isValidShouldReturnTrueForValidCertificate() {
        assertThat(CertificateUtils.isValid(validCertificate)).isTrue();
    }

    @Test
    @DisplayName("isValid should return false for expired certificate")
    void isValidShouldReturnFalseForExpiredCertificate() {
        assertThat(CertificateUtils.isValid(expiredCertificate)).isFalse();
    }

    @Test
    @DisplayName("isValid should return false for null certificate")
    void isValidShouldReturnFalseForNullCertificate() {
        assertThat(CertificateUtils.isValid(null)).isFalse();
    }

    @Test
    @DisplayName("expiresWithinDays should return true for expiring soon certificate")
    void expiresWithinDaysShouldReturnTrueForExpiringSoonCertificate() {
        // Valid certificate expires in 365 days
        assertThat(CertificateUtils.expiresWithinDays(validCertificate, 400)).isTrue();
    }

    @Test
    @DisplayName("expiresWithinDays should return false for certificate with time remaining")
    void expiresWithinDaysShouldReturnFalseForCertificateWithTimeRemaining() {
        // Valid certificate expires in 365 days
        assertThat(CertificateUtils.expiresWithinDays(validCertificate, 30)).isFalse();
    }

    @Test
    @DisplayName("expiresWithinDays should return true for null certificate")
    void expiresWithinDaysShouldReturnTrueForNullCertificate() {
        assertThat(CertificateUtils.expiresWithinDays(null, 30)).isTrue();
    }

    @Test
    @DisplayName("getCommonName should extract CN from certificate")
    void getCommonNameShouldExtractCnFromCertificate() {
        String cn = CertificateUtils.getCommonName(validCertificate);

        assertThat(cn).isEqualTo("test.example.com");
    }

    @Test
    @DisplayName("getCommonName should return null for null certificate")
    void getCommonNameShouldReturnNullForNullCertificate() {
        assertThat(CertificateUtils.getCommonName(null)).isNull();
    }

    @Test
    @DisplayName("getSerialNumber should return serial in hex format")
    void getSerialNumberShouldReturnSerialInHexFormat() {
        String serial = CertificateUtils.getSerialNumber(validCertificate);

        assertThat(serial).isNotNull();
        assertThat(serial).matches("[0-9a-f]+");
    }

    @Test
    @DisplayName("getSerialNumber should return null for null certificate")
    void getSerialNumberShouldReturnNullForNullCertificate() {
        assertThat(CertificateUtils.getSerialNumber(null)).isNull();
    }

    @Test
    @DisplayName("roundtrip PEM conversion should preserve certificate")
    void roundtripPemConversionShouldPreserveCertificate() {
        String pem = CertificateUtils.toPem(validCertificate);
        X509Certificate parsed = CertificateUtils.parseCertificate(pem);

        assertThat(parsed.getSubjectX500Principal())
            .isEqualTo(validCertificate.getSubjectX500Principal());
        assertThat(parsed.getSerialNumber())
            .isEqualTo(validCertificate.getSerialNumber());
    }

    @Test
    @DisplayName("computeSha256Fingerprint should compute fingerprint for valid certificate")
    void computeSha256FingerprintShouldComputeFingerprintForValidCertificate() {
        String fingerprint = CertificateUtils.computeSha256Fingerprint(validCertificate);

        assertThat(fingerprint).isNotNull();
        assertThat(fingerprint).startsWith("SHA256:");
        assertThat(fingerprint).hasSize(7 + 64); // "SHA256:" prefix + 64 hex chars
    }

    @Test
    @DisplayName("computeSha256Fingerprint should throw for null certificate")
    void computeSha256FingerprintShouldThrowForNullCertificate() {
        assertThatThrownBy(() -> CertificateUtils.computeSha256Fingerprint(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("fingerprintMatches should compare fingerprints correctly")
    void fingerprintMatchesShouldCompareFingerprintsCorrectly() {
        String fingerprint = CertificateUtils.computeSha256Fingerprint(validCertificate);

        assertThat(CertificateUtils.fingerprintMatches(fingerprint, fingerprint)).isTrue();
        assertThat(CertificateUtils.fingerprintMatches(fingerprint, fingerprint.toUpperCase())).isTrue();
    }

    @Test
    @DisplayName("fingerprintMatches should return false for different fingerprints")
    void fingerprintMatchesShouldReturnFalseForDifferentFingerprints() {
        String fingerprint = CertificateUtils.computeSha256Fingerprint(validCertificate);
        String differentFingerprint = "0".repeat(64);

        assertThat(CertificateUtils.fingerprintMatches(fingerprint, differentFingerprint)).isFalse();
    }

    @Test
    @DisplayName("fingerprintMatches should handle null inputs")
    void fingerprintMatchesShouldHandleNullInputs() {
        assertThat(CertificateUtils.fingerprintMatches(null, null)).isFalse();
        assertThat(CertificateUtils.fingerprintMatches("abc", null)).isFalse();
        assertThat(CertificateUtils.fingerprintMatches(null, "abc")).isFalse();
    }

    @Test
    @DisplayName("getDnsSubjectAltNames should return empty list for cert without SANs")
    void getDnsSubjectAltNamesShouldReturnEmptyListForCertWithoutSans() {
        List<String> sans = CertificateUtils.getDnsSubjectAltNames(validCertificate);

        assertThat(sans).isNotNull();
        // Our test cert doesn't have SANs, should return empty list
        assertThat(sans).isEmpty();
    }

    @Test
    @DisplayName("getDnsSubjectAltNames should return empty list for null certificate")
    void getDnsSubjectAltNamesShouldReturnEmptyListForNullCertificate() {
        assertThat(CertificateUtils.getDnsSubjectAltNames(null)).isEmpty();
    }

    @Test
    @DisplayName("getUriSubjectAltNames should return empty list for cert without SANs")
    void getUriSubjectAltNamesShouldReturnEmptyListForCertWithoutSans() {
        List<String> sans = CertificateUtils.getUriSubjectAltNames(validCertificate);

        assertThat(sans).isNotNull();
        assertThat(sans).isEmpty();
    }

    @Test
    @DisplayName("getUriSubjectAltNames should return empty list for null certificate")
    void getUriSubjectAltNamesShouldReturnEmptyListForNullCertificate() {
        assertThat(CertificateUtils.getUriSubjectAltNames(null)).isEmpty();
    }

    @Test
    @DisplayName("extractFqdn should return CN when no SANs")
    void extractFqdnShouldReturnCnWhenNoSans() {
        var fqdn = CertificateUtils.extractFqdn(validCertificate);

        assertThat(fqdn).isPresent();
        assertThat(fqdn.get()).isEqualTo("test.example.com");
    }

    @Test
    @DisplayName("extractFqdn should return empty for null certificate")
    void extractFqdnShouldReturnEmptyForNullCertificate() {
        assertThat(CertificateUtils.extractFqdn(null)).isEmpty();
    }

    @Test
    @DisplayName("extractAnsName should return empty when no URI SANs")
    void extractAnsNameShouldReturnEmptyWhenNoUriSans() {
        var ansName = CertificateUtils.extractAnsName(validCertificate);

        assertThat(ansName).isEmpty();
    }

    @Test
    @DisplayName("extractAnsName should return empty for null certificate")
    void extractAnsNameShouldReturnEmptyForNullCertificate() {
        assertThat(CertificateUtils.extractAnsName(null)).isEmpty();
    }

    @Test
    @DisplayName("getDnsSubjectAltNames should return DNS names from certificate with SANs")
    void getDnsSubjectAltNamesShouldReturnDnsNamesFromCertWithSans() {
        X509Certificate certWithSans = createCertificateWithSans("test.example.com",
            new Date(System.currentTimeMillis() - 86400000L),
            new Date(System.currentTimeMillis() + 86400000L * 365),
            new String[]{"san1.example.com", "san2.example.com"},
            null);

        List<String> sans = CertificateUtils.getDnsSubjectAltNames(certWithSans);

        assertThat(sans).containsExactlyInAnyOrder("san1.example.com", "san2.example.com");
    }

    @Test
    @DisplayName("getUriSubjectAltNames should return URI names from certificate with SANs")
    void getUriSubjectAltNamesShouldReturnUriNamesFromCertWithSans() {
        X509Certificate certWithSans = createCertificateWithSans("test.example.com",
            new Date(System.currentTimeMillis() - 86400000L),
            new Date(System.currentTimeMillis() + 86400000L * 365),
            null,
            new String[]{"ans://example.agent"});

        List<String> sans = CertificateUtils.getUriSubjectAltNames(certWithSans);

        assertThat(sans).containsExactly("ans://example.agent");
    }

    @Test
    @DisplayName("extractAnsName should return ANS URI from URI SAN")
    void extractAnsNameShouldReturnAnsUriFromUriSan() {
        X509Certificate certWithAns = createCertificateWithSans("test.example.com",
            new Date(System.currentTimeMillis() - 86400000L),
            new Date(System.currentTimeMillis() + 86400000L * 365),
            null,
            new String[]{"ans://my-agent.example"});

        var ansName = CertificateUtils.extractAnsName(certWithAns);

        assertThat(ansName).isPresent();
        assertThat(ansName.get()).isEqualTo("ans://my-agent.example");
    }

    @Test
    @DisplayName("extractFqdn should return first DNS SAN when available")
    void extractFqdnShouldReturnFirstDnsSanWhenAvailable() {
        X509Certificate certWithSans = createCertificateWithSans("test.example.com",
            new Date(System.currentTimeMillis() - 86400000L),
            new Date(System.currentTimeMillis() + 86400000L * 365),
            new String[]{"fqdn.example.com"},
            null);

        var fqdn = CertificateUtils.extractFqdn(certWithSans);

        assertThat(fqdn).isPresent();
        assertThat(fqdn.get()).isEqualTo("fqdn.example.com");
    }

    private static X509Certificate createCertificate(String cn, Date notBefore, Date notAfter) {
        try {
            KeyPairManager keyPairManager = new KeyPairManager();
            KeyPair keyPair = keyPairManager.generateRsaKeyPair();

            X500Name subject = new X500Name("CN=" + cn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
            );

            certBuilder.addExtension(
                Extension.basicConstraints, true, new BasicConstraints(false)
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

            return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));

        } catch (Exception e) {
            throw new RuntimeException("Failed to create test certificate", e);
        }
    }

    private static X509Certificate createCertificateWithSans(String cn, Date notBefore, Date notAfter,
            String[] dnsNames, String[] uriNames) {
        try {
            KeyPairManager keyPairManager = new KeyPairManager();
            KeyPair keyPair = keyPairManager.generateRsaKeyPair();

            X500Name subject = new X500Name("CN=" + cn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
            );

            certBuilder.addExtension(
                Extension.basicConstraints, true, new BasicConstraints(false)
            );

            // Add Subject Alternative Names
            java.util.List<GeneralName> sanList = new java.util.ArrayList<>();
            if (dnsNames != null) {
                for (String dns : dnsNames) {
                    sanList.add(new GeneralName(GeneralName.dNSName, dns));
                }
            }
            if (uriNames != null) {
                for (String uri : uriNames) {
                    sanList.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
                }
            }
            if (!sanList.isEmpty()) {
                GeneralNames sans = new GeneralNames(sanList.toArray(new GeneralName[0]));
                certBuilder.addExtension(Extension.subjectAlternativeName, false, sans);
            }

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

            return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));

        } catch (Exception e) {
            throw new RuntimeException("Failed to create test certificate with SANs", e);
        }
    }
}
