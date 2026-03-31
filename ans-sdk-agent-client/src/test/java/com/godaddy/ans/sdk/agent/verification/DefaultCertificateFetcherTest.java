package com.godaddy.ans.sdk.agent.verification;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for DefaultCertificateFetcher.
 */
class DefaultCertificateFetcherTest {

    @Nested
    @DisplayName("Singleton tests")
    class SingletonTests {

        @Test
        @DisplayName("INSTANCE should not be null")
        void instanceShouldNotBeNull() {
            assertThat(DefaultCertificateFetcher.INSTANCE).isNotNull();
        }

        @Test
        @DisplayName("INSTANCE should implement CertificateFetcher")
        void instanceShouldImplementCertificateFetcher() {
            assertThat(DefaultCertificateFetcher.INSTANCE).isInstanceOf(CertificateFetcher.class);
        }

        @Test
        @DisplayName("INSTANCE should be same reference")
        void instanceShouldBeSameReference() {
            CertificateFetcher first = DefaultCertificateFetcher.INSTANCE;
            CertificateFetcher second = DefaultCertificateFetcher.INSTANCE;
            assertThat(first).isSameAs(second);
        }
    }

    @Nested
    @DisplayName("getCertificate() tests")
    class GetCertificateTests {

        @Test
        @Disabled("Requires network access - run manually on dev machine to verify SSL certificate fetching")
        @DisplayName("Should fetch certificate from real host")
        void shouldFetchCertificateFromRealHost() throws IOException {
            // Connect to a well-known host
            X509Certificate cert = DefaultCertificateFetcher.INSTANCE
                .getCertificate("www.google.com", 443);

            assertThat(cert).isNotNull();
            assertThat(cert.getSubjectX500Principal()).isNotNull();
        }

        @Test
        @DisplayName("Should throw IOException for invalid hostname")
        void shouldThrowForInvalidHostname() {
            assertThatThrownBy(() ->
                DefaultCertificateFetcher.INSTANCE.getCertificate("invalid.host.that.does.not.exist.example", 443))
                .isInstanceOf(IOException.class);
        }

        @Test
        @DisplayName("Should throw IOException for connection refused")
        void shouldThrowForConnectionRefused() {
            // Port 1 is typically not listening
            assertThatThrownBy(() ->
                DefaultCertificateFetcher.INSTANCE.getCertificate("localhost", 1))
                .isInstanceOf(IOException.class);
        }
    }
}