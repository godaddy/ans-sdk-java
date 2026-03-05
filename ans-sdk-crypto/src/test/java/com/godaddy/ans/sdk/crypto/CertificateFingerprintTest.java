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
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CertificateFingerprintTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_ANS_NAME = "ans://v1.0.0.agent.example.com";

    @BeforeAll
    static void setup() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    @DisplayName("Should compute SHA-256 fingerprint")
    void shouldComputeSha256Fingerprint() {
        X509Certificate cert = createTestCertificate(TEST_HOSTNAME, null, null);

        String fingerprint = CertificateUtils.computeSha256Fingerprint(cert);

        assertThat(fingerprint).isNotNull();
        assertThat(fingerprint).startsWith("SHA256:");
        // Fingerprint should be 64 hex chars after prefix
        assertThat(fingerprint.substring(7)).hasSize(64);
        assertThat(fingerprint.substring(7)).matches("[0-9a-f]+");
    }

    @Test
    @DisplayName("Same certificate should produce same fingerprint")
    void sameCertificateShouldProduceSameFingerprint() {
        X509Certificate cert = createTestCertificate(TEST_HOSTNAME, null, null);

        String fp1 = CertificateUtils.computeSha256Fingerprint(cert);
        String fp2 = CertificateUtils.computeSha256Fingerprint(cert);

        assertThat(fp1).isEqualTo(fp2);
    }

    @Test
    @DisplayName("Different certificates should produce different fingerprints")
    void differentCertificatesShouldProduceDifferentFingerprints() {
        X509Certificate cert1 = createTestCertificate("host1.example.com", null, null);
        X509Certificate cert2 = createTestCertificate("host2.example.com", null, null);

        String fp1 = CertificateUtils.computeSha256Fingerprint(cert1);
        String fp2 = CertificateUtils.computeSha256Fingerprint(cert2);

        assertThat(fp1).isNotEqualTo(fp2);
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException for null certificate")
    void shouldThrowIllegalArgumentExceptionForNullCertificate() {

        assertThrows(IllegalArgumentException.class, () -> CertificateUtils.computeSha256Fingerprint(null));
    }

    @Test
    @DisplayName("Should match fingerprints case-insensitively")
    void shouldMatchFingerprintsCaseInsensitively() {
        String lower = "SHA256:abcdef0123456789";
        String upper = "SHA256:ABCDEF0123456789";

        assertThat(CertificateUtils.fingerprintMatches(lower, upper)).isTrue();
    }

    @Test
    @DisplayName("Should match fingerprints with different prefixes")
    void shouldMatchFingerprintsWithDifferentPrefixes() {
        String withPrefix = "SHA256:abcdef";
        String withDashPrefix = "SHA-256:abcdef";
        String noPrefix = "abcdef";

        assertThat(CertificateUtils.fingerprintMatches(withPrefix, withDashPrefix)).isTrue();
        assertThat(CertificateUtils.fingerprintMatches(withPrefix, noPrefix)).isTrue();
    }

    @Test
    @DisplayName("Should match fingerprints ignoring colons and spaces")
    void shouldMatchFingerprintsIgnoringColonsAndSpaces() {
        String plain = "SHA256:abcdef0123456789";
        String withColons = "SHA256:ab:cd:ef:01:23:45:67:89";
        String withSpaces = "SHA256:ab cd ef 01 23 45 67 89";

        assertThat(CertificateUtils.fingerprintMatches(plain, withColons)).isTrue();
        assertThat(CertificateUtils.fingerprintMatches(plain, withSpaces)).isTrue();
    }

    @Test
    @DisplayName("Should not match different fingerprints")
    void shouldNotMatchDifferentFingerprints() {
        String fp1 = "SHA256:abcdef";
        String fp2 = "SHA256:fedcba";

        assertThat(CertificateUtils.fingerprintMatches(fp1, fp2)).isFalse();
    }

    @Test
    @DisplayName("Should not match null fingerprints")
    void shouldNotMatchNullFingerprints() {
        assertThat(CertificateUtils.fingerprintMatches(null, "SHA256:abc")).isFalse();
        assertThat(CertificateUtils.fingerprintMatches("SHA256:abc", null)).isFalse();
        assertThat(CertificateUtils.fingerprintMatches(null, null)).isFalse();
    }

    @Test
    @DisplayName("Should extract DNS SANs from certificate")
    void shouldExtractDnsSansFromCertificate() {
        X509Certificate cert = createTestCertificate(
            TEST_HOSTNAME,
            List.of(TEST_HOSTNAME, "alt.example.com"),
            null
        );

        List<String> dnsNames = CertificateUtils.getDnsSubjectAltNames(cert);

        assertThat(dnsNames).containsExactlyInAnyOrder(TEST_HOSTNAME, "alt.example.com");
    }

    @Test
    @DisplayName("Should extract URI SANs from certificate")
    void shouldExtractUriSansFromCertificate() {
        X509Certificate cert = createTestCertificate(
            TEST_HOSTNAME,
            List.of(TEST_HOSTNAME),
            TEST_ANS_NAME
        );

        List<String> uris = CertificateUtils.getUriSubjectAltNames(cert);

        assertThat(uris).containsExactly(TEST_ANS_NAME);
    }

    @Test
    @DisplayName("Should extract ANS name from certificate")
    void shouldExtractAnsNameFromCertificate() {
        X509Certificate cert = createTestCertificate(
            TEST_HOSTNAME,
            List.of(TEST_HOSTNAME),
            TEST_ANS_NAME
        );

        Optional<String> ansName = CertificateUtils.extractAnsName(cert);

        assertThat(ansName).isPresent();
        assertThat(ansName.get()).isEqualTo(TEST_ANS_NAME);
    }

    @Test
    @DisplayName("Should extract FQDN from DNS SAN")
    void shouldExtractFqdnFromDnsSan() {
        X509Certificate cert = createTestCertificate(
            "cn.example.com", // CN
            List.of(TEST_HOSTNAME), // DNS SAN - should be preferred
            null
        );

        Optional<String> fqdn = CertificateUtils.extractFqdn(cert);

        assertThat(fqdn).isPresent();
        assertThat(fqdn.get()).isEqualTo(TEST_HOSTNAME);
    }

    @Test
    @DisplayName("Should extract FQDN from CN when no DNS SAN")
    void shouldExtractFqdnFromCnWhenNoDnsSan() {
        X509Certificate cert = createTestCertificate(TEST_HOSTNAME, null, null);

        Optional<String> fqdn = CertificateUtils.extractFqdn(cert);

        assertThat(fqdn).isPresent();
        assertThat(fqdn.get()).isEqualTo(TEST_HOSTNAME);
    }

    @Test
    @DisplayName("Should return empty for null certificate when extracting FQDN")
    void shouldReturnEmptyForNullCertificateWhenExtractingFqdn() {
        Optional<String> fqdn = CertificateUtils.extractFqdn(null);

        assertThat(fqdn).isEmpty();
    }

    @Test
    @DisplayName("Should return empty for null certificate when extracting ANS name")
    void shouldReturnEmptyForNullCertificateWhenExtractingAnsName() {
        Optional<String> ansName = CertificateUtils.extractAnsName(null);

        assertThat(ansName).isEmpty();
    }

    @Test
    @DisplayName("Should return empty list for DNS SANs on null certificate")
    void shouldReturnEmptyListForDnsSansOnNullCertificate() {
        List<String> dnsNames = CertificateUtils.getDnsSubjectAltNames(null);

        assertThat(dnsNames).isEmpty();
    }

    @Test
    @DisplayName("Should return empty list for URI SANs on null certificate")
    void shouldReturnEmptyListForUriSansOnNullCertificate() {
        List<String> uris = CertificateUtils.getUriSubjectAltNames(null);

        assertThat(uris).isEmpty();
    }

    /**
     * Creates a self-signed test certificate with optional SANs.
     */
    private X509Certificate createTestCertificate(String cn, List<String> dnsNames, String uriSan) {
        try {
            KeyPairManager keyPairManager = new KeyPairManager();
            KeyPair keyPair = keyPairManager.generateRsaKeyPair();

            X500Name subject = new X500Name("CN=" + cn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
            Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
            );

            // Add basic constraints
            certBuilder.addExtension(
                Extension.basicConstraints, true, new BasicConstraints(false)
            );

            // Add SANs if provided
            if ((dnsNames != null && !dnsNames.isEmpty()) || uriSan != null) {
                int count = (dnsNames != null ? dnsNames.size() : 0) + (uriSan != null ? 1 : 0);
                GeneralName[] names = new GeneralName[count];
                int i = 0;

                if (dnsNames != null) {
                    for (String dns : dnsNames) {
                        names[i++] = new GeneralName(GeneralName.dNSName, dns);
                    }
                }

                if (uriSan != null) {
                    names[i] = new GeneralName(GeneralName.uniformResourceIdentifier, uriSan);
                }

                certBuilder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(names)
                );
            }

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
}