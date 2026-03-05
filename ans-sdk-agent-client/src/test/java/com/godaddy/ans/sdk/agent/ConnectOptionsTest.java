package com.godaddy.ans.sdk.agent;

import com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

/**
 * Tests for ConnectOptions.
 */
class ConnectOptionsTest {

    @Test
    void defaultsShouldUsePkiOnlyPolicy() {
        ConnectOptions options = ConnectOptions.defaults();
        VerificationPolicy policy = options.getVerificationPolicy();
        assertEquals(VerificationMode.DISABLED, policy.daneMode());
        assertEquals(VerificationMode.DISABLED, policy.badgeMode());
    }

    @Test
    void defaultsShouldUsePort443() {
        ConnectOptions options = ConnectOptions.defaults();
        assertEquals(443, options.getPort());
    }

    @Test
    void defaultsShouldNotHaveClientCertificate() {
        ConnectOptions options = ConnectOptions.defaults();
        assertFalse(options.hasClientCertificate());
    }

    @Test
    void builderShouldSetPort() {
        ConnectOptions options = ConnectOptions.builder()
            .port(8443)
            .build();

        assertEquals(8443, options.getPort());
    }

    @Test
    void builderShouldRejectInvalidPort() {
        assertThrows(IllegalArgumentException.class, () ->
            ConnectOptions.builder().port(0).build());

        assertThrows(IllegalArgumentException.class, () ->
            ConnectOptions.builder().port(70000).build());
    }

    @Test
    void builderShouldSetClientCertPaths() {
        Path certPath = Path.of("/tmp/cert.pem");
        Path keyPath = Path.of("/tmp/key.pem");

        ConnectOptions options = ConnectOptions.builder()
            .clientCertPath(certPath, keyPath)
            .build();

        assertTrue(options.hasClientCertificate());
        assertEquals(certPath, options.getClientCertPath());
        assertEquals(keyPath, options.getClientKeyPath());
    }

    @Test
    void builderShouldRejectPartialCertPaths() {
        assertThrows(IllegalStateException.class, () ->
            ConnectOptions.builder()
                .clientCertPath(Path.of("/tmp/cert.pem"))
                .build());
    }

    @Test
    void toStringShouldIncludeKeyProperties() {
        ConnectOptions options = ConnectOptions.builder()
            .port(8443)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        String str = options.toString();
        assertTrue(str.contains("badge=REQUIRED"));
        assertTrue(str.contains("8443"));
    }

    // ==================== VerificationPolicy Tests ====================

    @Test
    void builderShouldSetVerificationPolicy() {
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        VerificationPolicy policy = options.getVerificationPolicy();
        assertEquals(VerificationMode.REQUIRED, policy.badgeMode());
        assertEquals(VerificationMode.DISABLED, policy.daneMode());
    }

    @Test
    void customPolicyShouldBeUsedDirectly() {
        VerificationPolicy custom = VerificationPolicy.custom()
            .dane(VerificationMode.ADVISORY)
            .badge(VerificationMode.REQUIRED)
            .build();

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(custom)
            .build();

        assertSame(custom, options.getVerificationPolicy());
    }

    @Test
    void daneAndBadgePolicyShouldWork() {
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
            .build();

        VerificationPolicy policy = options.getVerificationPolicy();
        assertEquals(VerificationMode.REQUIRED, policy.daneMode());
        assertEquals(VerificationMode.REQUIRED, policy.badgeMode());
    }

    @Test
    void fullPolicyShouldEnableAllVerifications() {
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.FULL)
            .build();

        VerificationPolicy policy = options.getVerificationPolicy();
        assertEquals(VerificationMode.REQUIRED, policy.daneMode());
        assertEquals(VerificationMode.REQUIRED, policy.badgeMode());
    }

    @Test
    void customPolicyWithAdvisoryModes() {
        VerificationPolicy custom = VerificationPolicy.custom()
            .dane(VerificationMode.ADVISORY)
            .badge(VerificationMode.REQUIRED)
            .build();

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(custom)
            .build();

        VerificationPolicy policy = options.getVerificationPolicy();
        assertEquals(VerificationMode.ADVISORY, policy.daneMode());
        assertEquals(VerificationMode.REQUIRED, policy.badgeMode());
    }

    // ==================== Additional Builder Coverage Tests ====================

    @Test
    void builderShouldRejectNullVerificationPolicy() {
        assertThrows(NullPointerException.class, () ->
            ConnectOptions.builder().verificationPolicy(null));
    }

    @Test
    void builderShouldSetClientCertPathSeparately() {
        Path certPath = Path.of("/tmp/cert.pem");
        Path keyPath = Path.of("/tmp/key.pem");

        ConnectOptions options = ConnectOptions.builder()
            .clientCertPath(certPath)
            .clientKeyPath(keyPath)
            .build();

        assertTrue(options.hasClientCertificate());
        assertEquals(certPath, options.getClientCertPath());
        assertEquals(keyPath, options.getClientKeyPath());
    }

    @Test
    void builderShouldRejectNullCertPath() {
        assertThrows(IllegalArgumentException.class, () ->
            ConnectOptions.builder().clientCertPath(null));
    }

    @Test
    void builderShouldRejectNullKeyPath() {
        assertThrows(IllegalArgumentException.class, () ->
            ConnectOptions.builder().clientKeyPath(null));
    }

    @Test
    void builderShouldRejectEmptyCertPath() {
        assertThrows(IllegalArgumentException.class, () ->
            ConnectOptions.builder().clientCertPath(Path.of("")));
    }

    @Test
    void builderShouldRejectEmptyKeyPath() {
        assertThrows(IllegalArgumentException.class, () ->
            ConnectOptions.builder().clientKeyPath(Path.of("")));
    }

    @Test
    void builderShouldSetClientKeyPassword() {
        ConnectOptions options = ConnectOptions.builder()
            .clientCertPath(Path.of("/tmp/cert.pem"), Path.of("/tmp/key.pem"))
            .clientKeyPassword("secret123")
            .build();

        assertEquals("secret123", options.getClientKeyPassword());
    }

    @Test
    void builderShouldAcceptNullClientKeyPassword() {
        ConnectOptions options = ConnectOptions.builder()
            .clientKeyPassword(null)
            .build();

        assertNull(options.getClientKeyPassword());
    }

    @Test
    void builderShouldSetClientCertificateDirectly() {
        X509Certificate mockCert = mock(X509Certificate.class);
        PrivateKey mockKey = mock(PrivateKey.class);

        ConnectOptions options = ConnectOptions.builder()
            .clientCertificate(mockCert, mockKey)
            .build();

        assertTrue(options.hasClientCertificate());
        assertSame(mockCert, options.getClientCert());
        assertSame(mockKey, options.getClientKey());
    }

    @Test
    void builderShouldRejectNullCertificateInClientCertificate() {
        PrivateKey mockKey = mock(PrivateKey.class);

        assertThrows(NullPointerException.class, () ->
            ConnectOptions.builder().clientCertificate(null, mockKey));
    }

    @Test
    void builderShouldRejectNullKeyInClientCertificate() {
        X509Certificate mockCert = mock(X509Certificate.class);

        assertThrows(NullPointerException.class, () ->
            ConnectOptions.builder().clientCertificate(mockCert, null));
    }

    @Test
    void builderShouldRejectPartialClientCertOnly() {
        X509Certificate mockCert = mock(X509Certificate.class);

        // This should fail because we can't set clientCert without clientKey
        // The builder validates this in build()
        assertThrows(NullPointerException.class, () ->
            ConnectOptions.builder().clientCertificate(mockCert, null));
    }

    @Test
    void builderShouldSetTransparencyClient() {
        TransparencyClient mockClient = mock(TransparencyClient.class);

        ConnectOptions options = ConnectOptions.builder()
            .transparencyClient(mockClient)
            .build();

        assertSame(mockClient, options.getTransparencyClient());
    }

    @Test
    void builderShouldAcceptNullTransparencyClient() {
        ConnectOptions options = ConnectOptions.builder()
            .transparencyClient(null)
            .build();

        assertNull(options.getTransparencyClient());
    }

    @Test
    void builderShouldSetAuthProvider() {
        HttpAuthHeadersProvider authProvider = HttpAuthHeadersProvider.bearer("test-token");

        ConnectOptions options = ConnectOptions.builder()
            .authProvider(authProvider)
            .build();

        assertNotNull(options.getAuthProvider());
        assertSame(authProvider, options.getAuthProvider());
    }

    @Test
    void builderShouldAcceptNullAuthProvider() {
        ConnectOptions options = ConnectOptions.builder()
            .authProvider(null)
            .build();

        assertNull(options.getAuthProvider());
    }

    @Test
    void defaultsShouldReturnNullForOptionalFields() {
        ConnectOptions options = ConnectOptions.defaults();

        assertNull(options.getClientCertPath());
        assertNull(options.getClientKeyPath());
        assertNull(options.getClientKeyPassword());
        assertNull(options.getClientCert());
        assertNull(options.getClientKey());
        assertNull(options.getTransparencyClient());
        assertNull(options.getAuthProvider());
    }

    @Test
    void hasClientCertificateShouldReturnTrueForDirectCert() {
        X509Certificate mockCert = mock(X509Certificate.class);
        PrivateKey mockKey = mock(PrivateKey.class);

        ConnectOptions options = ConnectOptions.builder()
            .clientCertificate(mockCert, mockKey)
            .build();

        assertTrue(options.hasClientCertificate());
    }

    @Test
    void hasClientCertificateShouldReturnTrueForPaths() {
        ConnectOptions options = ConnectOptions.builder()
            .clientCertPath(Path.of("/tmp/cert.pem"), Path.of("/tmp/key.pem"))
            .build();

        assertTrue(options.hasClientCertificate());
    }

    @Test
    void toStringShouldIncludeAuthProviderStatus() {
        HttpAuthHeadersProvider authProvider = HttpAuthHeadersProvider.bearer("token");

        ConnectOptions options = ConnectOptions.builder()
            .authProvider(authProvider)
            .build();

        String str = options.toString();
        assertTrue(str.contains("hasAuthProvider=true"));
    }

    @Test
    void toStringShouldShowNoAuthProvider() {
        ConnectOptions options = ConnectOptions.defaults();

        String str = options.toString();
        assertTrue(str.contains("hasAuthProvider=false"));
    }

    @Test
    void builderShouldRejectPartialKeyPath() {
        // Only setting keyPath without certPath should fail at build
        assertThrows(IllegalStateException.class, () ->
            ConnectOptions.builder()
                .clientKeyPath(Path.of("/tmp/key.pem"))
                .build());
    }
}