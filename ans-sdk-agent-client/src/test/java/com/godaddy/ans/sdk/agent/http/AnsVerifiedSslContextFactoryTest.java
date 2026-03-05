package com.godaddy.ans.sdk.agent.http;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AnsVerifiedSslContextFactory}.
 */
class AnsVerifiedSslContextFactoryTest {

    @AfterEach
    void tearDown() {
        CertificateCapturingTrustManager.clearCapturedCertificates();
    }

    @Test
    void createReturnsValidSslContext() throws Exception {
        // When
        SSLContext sslContext = AnsVerifiedSslContextFactory.create();

        // Then
        assertThat(sslContext).isNotNull();
        // Protocol is "TLS" which allows negotiation to TLS 1.2 or 1.3
        assertThat(sslContext.getProtocol()).startsWith("TLS");
    }

    @Test
    void createUsesCertificateCapturingTrustManager() throws Exception {
        // When
        SSLContext sslContext = AnsVerifiedSslContextFactory.create();

        // Then - verify the SSLContext has a session context (indicating it was initialized)
        assertThat(sslContext.getServerSessionContext()).isNotNull();
        assertThat(sslContext.getClientSessionContext()).isNotNull();
    }

    @Test
    void createWithKeyStoreReturnsValidSslContext() throws Exception {
        // Given - create an empty KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        // When
        SSLContext sslContext = AnsVerifiedSslContextFactory.create(keyStore, "changeit".toCharArray());

        // Then
        assertThat(sslContext).isNotNull();
        assertThat(sslContext.getProtocol()).startsWith("TLS");
    }

    @Test
    void createWithNullKeyStoreUsesServerOnlyMode() throws Exception {
        // When - null keystore is valid (no client auth)
        SSLContext sslContext = AnsVerifiedSslContextFactory.create(null, null);

        // Then
        assertThat(sslContext).isNotNull();
        assertThat(sslContext.getProtocol()).startsWith("TLS");
    }
}
