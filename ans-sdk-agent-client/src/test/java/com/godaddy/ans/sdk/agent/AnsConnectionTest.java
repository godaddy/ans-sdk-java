package com.godaddy.ans.sdk.agent;

import com.godaddy.ans.sdk.agent.http.CertificateCapturingTrustManager;
import com.godaddy.ans.sdk.agent.verification.DefaultConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult.VerificationType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnsConnectionTest {

    private static final String TEST_HOSTNAME = "test.example.com";

    @Mock
    private PreVerificationResult mockPreResult;

    @Mock
    private DefaultConnectionVerifier mockVerifier;

    private VerificationPolicy policy = VerificationPolicy.SCITT_REQUIRED;

    private AnsConnection connection;

    @BeforeEach
    void setUp() {
        connection = new AnsConnection(TEST_HOSTNAME, mockPreResult, mockVerifier, policy);
    }

    @AfterEach
    void tearDown() {
        // Clean up any captured certificates
        CertificateCapturingTrustManager.clearCapturedCertificates(TEST_HOSTNAME);
    }

    @Nested
    @DisplayName("Accessor tests")
    class AccessorTests {

        @Test
        @DisplayName("hostname() returns the hostname")
        void hostnameShouldReturnHostname() {
            assertThat(connection.hostname()).isEqualTo(TEST_HOSTNAME);
        }

        @Test
        @DisplayName("preVerifyResult() returns the pre-verification result")
        void preVerifyResultShouldReturnPreResult() {
            assertThat(connection.preVerifyResult()).isSameAs(mockPreResult);
        }
    }

    @Nested
    @DisplayName("hasScittArtifacts() tests")
    class HasScittArtifactsTests {

        @Test
        @DisplayName("Should return true when pre-result has SCITT expectation")
        void shouldReturnTrueWhenScittPresent() {
            when(mockPreResult.hasScittExpectation()).thenReturn(true);

            assertThat(connection.hasScittArtifacts()).isTrue();
        }

        @Test
        @DisplayName("Should return false when pre-result has no SCITT expectation")
        void shouldReturnFalseWhenScittAbsent() {
            when(mockPreResult.hasScittExpectation()).thenReturn(false);

            assertThat(connection.hasScittArtifacts()).isFalse();
        }
    }

    @Nested
    @DisplayName("hasBadgeRegistration() tests")
    class HasBadgeRegistrationTests {

        @Test
        @DisplayName("Should return true when pre-result has badge expectation")
        void shouldReturnTrueWhenBadgePresent() {
            when(mockPreResult.hasBadgeExpectation()).thenReturn(true);

            assertThat(connection.hasBadgeRegistration()).isTrue();
        }

        @Test
        @DisplayName("Should return false when pre-result has no badge expectation")
        void shouldReturnFalseWhenBadgeAbsent() {
            when(mockPreResult.hasBadgeExpectation()).thenReturn(false);

            assertThat(connection.hasBadgeRegistration()).isFalse();
        }
    }

    @Nested
    @DisplayName("hasDaneRecords() tests")
    class HasDaneRecordsTests {

        @Test
        @DisplayName("Should return true when pre-result has DANE expectation")
        void shouldReturnTrueWhenDanePresent() {
            when(mockPreResult.hasDaneExpectation()).thenReturn(true);

            assertThat(connection.hasDaneRecords()).isTrue();
        }

        @Test
        @DisplayName("Should return false when pre-result has no DANE expectation")
        void shouldReturnFalseWhenDaneAbsent() {
            when(mockPreResult.hasDaneExpectation()).thenReturn(false);

            assertThat(connection.hasDaneRecords()).isFalse();
        }
    }

    @Nested
    @DisplayName("verifyServer() tests")
    class VerifyServerTests {

        @Test
        @DisplayName("Should throw SecurityException when no certificates captured")
        void shouldThrowWhenNoCertificates() {
            // No certificates captured for this hostname

            assertThatThrownBy(() -> connection.verifyServer())
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("No server certificate captured");
        }

        @Test
        @DisplayName("Should verify with provided certificate")
        void shouldVerifyWithProvidedCertificate() {
            X509Certificate cert = mock(X509Certificate.class);
            List<VerificationResult> results = List.of(
                VerificationResult.success(VerificationType.SCITT, "fingerprint", "Server SCITT verified")
            );
            VerificationResult combined = VerificationResult.success(VerificationType.SCITT, "fingerprint", "Combined");

            when(mockVerifier.postVerify(eq(TEST_HOSTNAME), eq(cert), eq(mockPreResult)))
                .thenReturn(results);
            when(mockVerifier.combine(eq(results), eq(policy))).thenReturn(combined);

            VerificationResult result = connection.verifyServer(cert);

            assertThat(result).isSameAs(combined);
            verify(mockVerifier).postVerify(TEST_HOSTNAME, cert, mockPreResult);
            verify(mockVerifier).combine(results, policy);
        }
    }

    @Nested
    @DisplayName("verifyServerDetailed() tests")
    class VerifyServerDetailedTests {

        @Test
        @DisplayName("Should throw SecurityException when no certificates captured")
        void shouldThrowWhenNoCertificates() {
            assertThatThrownBy(() -> connection.verifyServerDetailed())
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("No server certificate captured");
        }

        @Test
        @DisplayName("Should return detailed results with provided certificate")
        void shouldReturnDetailedResultsWithProvidedCert() {
            X509Certificate cert = mock(X509Certificate.class);
            List<VerificationResult> expectedResults = List.of(
                VerificationResult.success(VerificationType.SCITT, "fingerprint", "SCITT OK"),
                VerificationResult.notFound(VerificationType.DANE, "DANE record not found")
            );

            when(mockVerifier.postVerify(eq(TEST_HOSTNAME), eq(cert), eq(mockPreResult)))
                .thenReturn(expectedResults);

            List<VerificationResult> results = connection.verifyServerDetailed(cert);

            assertThat(results).isEqualTo(expectedResults);
        }
    }

    @Nested
    @DisplayName("close() tests")
    class CloseTests {

        @Test
        @DisplayName("Should clear captured certificates on close")
        void shouldClearCapturedCertificatesOnClose() {
            // The close method clears captured certs - verify it doesn't throw
            connection.close();

            // Verify that getting certificates returns null/empty after close
            X509Certificate[] certs = CertificateCapturingTrustManager.getCapturedCertificates(TEST_HOSTNAME);
            assertThat(certs).isNull();
        }
    }

    @Nested
    @DisplayName("AutoCloseable behavior tests")
    class AutoCloseableTests {

        @Test
        @DisplayName("Should work in try-with-resources")
        void shouldWorkInTryWithResources() {
            X509Certificate cert = mock(X509Certificate.class);
            VerificationResult successResult = VerificationResult.success(VerificationType.SCITT, "fingerprint", "OK");

            when(mockVerifier.postVerify(any(), any(), any())).thenReturn(List.of(successResult));
            when(mockVerifier.combine(any(), any())).thenReturn(successResult);

            try (AnsConnection conn = new AnsConnection(TEST_HOSTNAME, mockPreResult, mockVerifier, policy)) {
                VerificationResult result = conn.verifyServer(cert);
                assertThat(result.isSuccess()).isTrue();
            }

            // After close, captured certs should be cleared
            X509Certificate[] certs = CertificateCapturingTrustManager.getCapturedCertificates(TEST_HOSTNAME);
            assertThat(certs).isNull();
        }
    }
}
