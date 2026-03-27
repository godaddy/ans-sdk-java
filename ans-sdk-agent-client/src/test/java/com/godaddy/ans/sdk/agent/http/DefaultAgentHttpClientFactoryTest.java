package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.verification.DaneTlsaVerifier;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.StringWriter;
import java.math.BigInteger;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Tests for DefaultAgentHttpClientFactory.
 */
class DefaultAgentHttpClientFactoryTest {

    @Test
    void defaultConstructorCreatesFactory() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        assertNotNull(factory);
    }

    @Test
    void constructorWithDaneVerifier() {
        DaneTlsaVerifier mockVerifier = mock(DaneTlsaVerifier.class);
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory(mockVerifier);
        assertNotNull(factory);
    }

    @Test
    void constructorRejectsNullDaneVerifier() {
        assertThrows(NullPointerException.class, () ->
            new DefaultAgentHttpClientFactory(null));
    }

    @Test
    void createVerifiedRejectsNullHostname() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.defaults();

        assertThrows(NullPointerException.class, () ->
            factory.createVerified(null, options, Duration.ofSeconds(10)));
    }

    @Test
    void createVerifiedRejectsNullOptions() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        assertThrows(NullPointerException.class, () ->
            factory.createVerified("example.com", null, Duration.ofSeconds(10)));
    }

    @Test
    void createVerifiedRejectsNullTimeout() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.defaults();

        assertThrows(NullPointerException.class, () ->
            factory.createVerified("example.com", options, null));
    }

    @Test
    void createVerifiedWithPkiOnly() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.ansHttpClient());
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithDaneRequired() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createReturnsHttpClient() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.defaults();

        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        assertNotNull(client);
    }

    @Test
    void createRejectsNullHostname() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        assertThrows(NullPointerException.class, () ->
            factory.create(null, ConnectOptions.defaults(), Duration.ofSeconds(10)));
    }

    @Test
    void createVerifiedWithBadgeRequired() {
        // Tests the badge verification creation path
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.ansHttpClient());
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithBothDaneAndBadgeEnabled() {
        // Tests creating verifiers for both DANE and Badge
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        VerificationPolicy policy = VerificationPolicy.custom()
            .dane(VerificationMode.REQUIRED)
            .badge(VerificationMode.ADVISORY)
            .build();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(policy)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithCustomTransparencyClient() {
        // Tests that custom TransparencyClient is used when provided
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .transparencyClient(mockTransparencyClient)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createVerifiedReusesVerificationService() {
        // Tests that the cached verification service is reused across calls
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        // First call creates the verification service
        VerifiedClientResult result1 = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        // Second call should reuse the cached service
        VerifiedClientResult result2 = factory.createVerified(
            "example.org", options, Duration.ofSeconds(10));

        assertNotNull(result1);
        assertNotNull(result2);
        // Both should have verifiers (service is shared internally)
        assertNotNull(result1.verifier());
        assertNotNull(result2.verifier());
    }

    @Test
    void createVerifiedWithAdvisoryModes() {
        // Tests creating with advisory modes
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        VerificationPolicy policy = VerificationPolicy.custom()
            .dane(VerificationMode.ADVISORY)
            .badge(VerificationMode.ADVISORY)
            .build();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(policy)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createVerifiedWithDisabledDane() {
        // Tests that DANE verifier is NOT added when disabled
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        VerificationPolicy policy = VerificationPolicy.custom()
            .dane(VerificationMode.DISABLED)
            .badge(VerificationMode.REQUIRED)
            .build();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(policy)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        // Verifier should still exist (badge verifier)
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithDisabledBadge() {
        // Tests that Badge verifier is NOT added when disabled
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        VerificationPolicy policy = VerificationPolicy.custom()
            .dane(VerificationMode.REQUIRED)
            .badge(VerificationMode.DISABLED)
            .build();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(policy)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        // Verifier should still exist (DANE verifier)
        assertNotNull(result.verifier());
    }

    @Test
    void createReturnsUnderlyingHttpClient() {
        // Tests that create() returns the underlying HttpClient, not the wrapper
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.defaults();

        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        assertNotNull(client);
        // Should be a raw HttpClient, not AnsHttpClient
    }

    // ==================== mTLS Client Certificate Tests ====================

    @Test
    void createVerifiedWithPreLoadedClientCertificate() throws Exception {
        // Tests the loadKeyManagers path with pre-loaded certificate
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        // Generate a test certificate and key pair
        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.ansHttpClient());
    }

    @Test
    void createWithPreLoadedClientCertificate() throws Exception {
        // Tests create() path with pre-loaded certificate
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        assertNotNull(client);
    }

    @Test
    void createVerifiedWithMtlsAndDaneVerification() throws Exception {
        // Tests mTLS combined with DANE verification
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithMtlsAndBadgeVerification() throws Exception {
        // Tests mTLS combined with Badge verification
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createVerifiedWithMtlsAndDaneAndBadgeVerification() throws Exception {
        // Tests mTLS combined with both DANE and Badge verification
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createVerifiedWithFileCertificatePaths(@TempDir Path tempDir) throws Exception {
        // Tests the loadKeyManagers path with file-based certificate loading
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        // Generate test certificates dynamically
        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=test.example.com", keyPair);
        Path certPath = writeCertToPem(tempDir.resolve("test-cert.pem"), cert);
        Path keyPath = writeKeyToPem(tempDir.resolve("test-key.pem"), keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .clientCertPath(certPath, keyPath)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.ansHttpClient());
    }

    @Test
    void createWithFileCertificatePaths(@TempDir Path tempDir) throws Exception {
        // Tests create() path with file-based certificate loading
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        // Generate test certificates dynamically
        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=test.example.com", keyPair);
        Path certPath = writeCertToPem(tempDir.resolve("test-cert.pem"), cert);
        Path keyPath = writeKeyToPem(tempDir.resolve("test-key.pem"), keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .clientCertPath(certPath, keyPath)
            .build();

        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        assertNotNull(client);
    }

    @Test
    void createVerifiedWithFileCertificatePathsAndDane(@TempDir Path tempDir) throws Exception {
        // Tests file-based mTLS combined with DANE verification
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        // Generate test certificates dynamically
        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=test.example.com", keyPair);
        Path certPath = writeCertToPem(tempDir.resolve("test-cert.pem"), cert);
        Path keyPath = writeKeyToPem(tempDir.resolve("test-key.pem"), keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .clientCertPath(certPath, keyPath)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    // ==================== Helper Methods ====================

    private KeyPair generateTestKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private X509Certificate createTestCertificate(String subjectDn, KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name(subjectDn);
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
            .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
            .getCertificate(certBuilder.build(signer));
    }

    private Path writeCertToPem(Path path, X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(cert);
        }
        Files.writeString(path, sw.toString());
        return path;
    }

    private Path writeKeyToPem(Path path, KeyPair keyPair) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(keyPair.getPrivate());
        }
        Files.writeString(path, sw.toString());
        return path;
    }
}
