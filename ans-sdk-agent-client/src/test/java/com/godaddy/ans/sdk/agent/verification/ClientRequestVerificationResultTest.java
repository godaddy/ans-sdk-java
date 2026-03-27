package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.transparency.scitt.ScittReceipt;
import com.godaddy.ans.sdk.transparency.scitt.StatusToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientRequestVerificationResultTest {

    @Nested
    @DisplayName("Constructor validation tests")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Should throw NullPointerException when errors is null")
        void shouldThrowWhenErrorsNull() {
            assertThatThrownBy(() -> new ClientRequestVerificationResult(
                true,
                "agent-123",
                mock(StatusToken.class),
                mock(ScittReceipt.class),
                mock(X509Certificate.class),
                null,
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(100)
            )).isInstanceOf(NullPointerException.class)
                .hasMessageContaining("errors cannot be null");
        }

        @Test
        @DisplayName("Should throw NullPointerException when policyUsed is null")
        void shouldThrowWhenPolicyNull() {
            assertThatThrownBy(() -> new ClientRequestVerificationResult(
                true,
                "agent-123",
                mock(StatusToken.class),
                mock(ScittReceipt.class),
                mock(X509Certificate.class),
                List.of(),
                null,
                Duration.ofMillis(100)
            )).isInstanceOf(NullPointerException.class)
                .hasMessageContaining("policyUsed cannot be null");
        }

        @Test
        @DisplayName("Should throw NullPointerException when verificationDuration is null")
        void shouldThrowWhenDurationNull() {
            assertThatThrownBy(() -> new ClientRequestVerificationResult(
                true,
                "agent-123",
                mock(StatusToken.class),
                mock(ScittReceipt.class),
                mock(X509Certificate.class),
                List.of(),
                VerificationPolicy.SCITT_REQUIRED,
                null
            )).isInstanceOf(NullPointerException.class)
                .hasMessageContaining("verificationDuration cannot be null");
        }

        @Test
        @DisplayName("Should create defensive copy of errors list")
        void shouldCreateDefensiveCopyOfErrors() {
            List<String> errors = new ArrayList<>();
            errors.add("error1");

            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                false,
                null,
                null,
                null,
                null,
                errors,
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(100)
            );

            // Modify original list
            errors.add("error2");

            // Result should not be affected
            assertThat(result.errors()).containsExactly("error1");
        }
    }

    @Nested
    @DisplayName("Factory method tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("success() should create verified result")
        void successShouldCreateVerifiedResult() {
            StatusToken token = mock(StatusToken.class);
            ScittReceipt receipt = mock(ScittReceipt.class);
            X509Certificate cert = mock(X509Certificate.class);
            Duration duration = Duration.ofMillis(150);

            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "agent-123",
                token,
                receipt,
                cert,
                VerificationPolicy.SCITT_REQUIRED,
                duration
            );

            assertThat(result.verified()).isTrue();
            assertThat(result.agentId()).isEqualTo("agent-123");
            assertThat(result.statusToken()).isSameAs(token);
            assertThat(result.receipt()).isSameAs(receipt);
            assertThat(result.clientCertificate()).isSameAs(cert);
            assertThat(result.errors()).isEmpty();
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.SCITT_REQUIRED);
            assertThat(result.verificationDuration()).isEqualTo(duration);
        }

        @Test
        @DisplayName("failure() with list should create failed result")
        void failureWithListShouldCreateFailedResult() {
            StatusToken token = mock(StatusToken.class);
            when(token.agentId()).thenReturn("extracted-agent-id");
            ScittReceipt receipt = mock(ScittReceipt.class);
            X509Certificate cert = mock(X509Certificate.class);
            List<String> errors = List.of("error1", "error2");
            Duration duration = Duration.ofMillis(200);

            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                errors,
                token,
                receipt,
                cert,
                VerificationPolicy.BADGE_REQUIRED,
                duration
            );

            assertThat(result.verified()).isFalse();
            assertThat(result.agentId()).isEqualTo("extracted-agent-id");
            assertThat(result.statusToken()).isSameAs(token);
            assertThat(result.receipt()).isSameAs(receipt);
            assertThat(result.clientCertificate()).isSameAs(cert);
            assertThat(result.errors()).containsExactly("error1", "error2");
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.BADGE_REQUIRED);
            assertThat(result.verificationDuration()).isEqualTo(duration);
        }

        @Test
        @DisplayName("failure() with single error should create failed result")
        void failureWithSingleErrorShouldCreateFailedResult() {
            X509Certificate cert = mock(X509Certificate.class);
            Duration duration = Duration.ofMillis(50);

            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                "Single error message",
                cert,
                VerificationPolicy.PKI_ONLY,
                duration
            );

            assertThat(result.verified()).isFalse();
            assertThat(result.agentId()).isNull();
            assertThat(result.statusToken()).isNull();
            assertThat(result.receipt()).isNull();
            assertThat(result.clientCertificate()).isSameAs(cert);
            assertThat(result.errors()).containsExactly("Single error message");
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.PKI_ONLY);
            assertThat(result.verificationDuration()).isEqualTo(duration);
        }

        @Test
        @DisplayName("failure() should extract agent ID from null token")
        void failureShouldHandleNullToken() {
            X509Certificate cert = mock(X509Certificate.class);

            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                List.of("error"),
                null,
                null,
                cert,
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(100)
            );

            assertThat(result.agentId()).isNull();
        }
    }

    @Nested
    @DisplayName("Helper method tests")
    class HelperMethodTests {

        @Test
        @DisplayName("hasScittArtifacts() returns true when both are present")
        void hasScittArtifactsReturnsTrue() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "agent",
                mock(StatusToken.class),
                mock(ScittReceipt.class),
                mock(X509Certificate.class),
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ZERO
            );

            assertThat(result.hasScittArtifacts()).isTrue();
        }

        @Test
        @DisplayName("hasScittArtifacts() returns false when receipt is null")
        void hasScittArtifactsReturnsFalseNoReceipt() {
            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                true, "agent", mock(StatusToken.class), null,
                mock(X509Certificate.class), List.of(), VerificationPolicy.SCITT_REQUIRED, Duration.ZERO
            );

            assertThat(result.hasScittArtifacts()).isFalse();
        }

        @Test
        @DisplayName("hasScittArtifacts() returns false when token is null")
        void hasScittArtifactsReturnsFalseNoToken() {
            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                true, "agent", null, mock(ScittReceipt.class),
                mock(X509Certificate.class), List.of(), VerificationPolicy.SCITT_REQUIRED, Duration.ZERO
            );

            assertThat(result.hasScittArtifacts()).isFalse();
        }

        @Test
        @DisplayName("hasStatusTokenOnly() returns true when token present but not receipt")
        void hasStatusTokenOnlyReturnsTrue() {
            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                true, "agent", mock(StatusToken.class), null,
                mock(X509Certificate.class), List.of(), VerificationPolicy.SCITT_REQUIRED, Duration.ZERO
            );

            assertThat(result.hasStatusTokenOnly()).isTrue();
        }

        @Test
        @DisplayName("hasStatusTokenOnly() returns false when both present")
        void hasStatusTokenOnlyReturnsFalseBothPresent() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "agent",
                mock(StatusToken.class),
                mock(ScittReceipt.class),
                mock(X509Certificate.class),
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ZERO
            );

            assertThat(result.hasStatusTokenOnly()).isFalse();
        }

        @Test
        @DisplayName("hasAnyScittArtifact() returns true with only receipt")
        void hasAnyScittArtifactReturnsTrueOnlyReceipt() {
            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                true, "agent", null, mock(ScittReceipt.class),
                mock(X509Certificate.class), List.of(), VerificationPolicy.SCITT_REQUIRED, Duration.ZERO
            );

            assertThat(result.hasAnyScittArtifact()).isTrue();
        }

        @Test
        @DisplayName("hasAnyScittArtifact() returns true with only token")
        void hasAnyScittArtifactReturnsTrueOnlyToken() {
            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                true, "agent", mock(StatusToken.class), null,
                mock(X509Certificate.class), List.of(), VerificationPolicy.SCITT_REQUIRED, Duration.ZERO
            );

            assertThat(result.hasAnyScittArtifact()).isTrue();
        }

        @Test
        @DisplayName("hasAnyScittArtifact() returns false with neither")
        void hasAnyScittArtifactReturnsFalseNeither() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                "error",
                mock(X509Certificate.class),
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ZERO
            );

            assertThat(result.hasAnyScittArtifact()).isFalse();
        }

        @Test
        @DisplayName("isCertificateTrusted() returns true when verified with token")
        void isCertificateTrustedReturnsTrue() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "agent",
                mock(StatusToken.class),
                mock(ScittReceipt.class),
                mock(X509Certificate.class),
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ZERO
            );

            assertThat(result.isCertificateTrusted()).isTrue();
        }

        @Test
        @DisplayName("isCertificateTrusted() returns false when not verified")
        void isCertificateTrustedReturnsFalseNotVerified() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                List.of("error"),
                mock(StatusToken.class),
                mock(ScittReceipt.class),
                mock(X509Certificate.class),
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ZERO
            );

            assertThat(result.isCertificateTrusted()).isFalse();
        }

        @Test
        @DisplayName("isCertificateTrusted() returns false when verified without token")
        void isCertificateTrustedReturnsFalseNoToken() {
            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                true, "agent", null, mock(ScittReceipt.class),
                mock(X509Certificate.class), List.of(), VerificationPolicy.SCITT_REQUIRED, Duration.ZERO
            );

            assertThat(result.isCertificateTrusted()).isFalse();
        }
    }

    @Nested
    @DisplayName("toString() tests")
    class ToStringTests {

        @Test
        @DisplayName("toString() for verified result includes agentId and duration")
        void toStringForVerifiedResult() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "test-agent-id",
                mock(StatusToken.class),
                mock(ScittReceipt.class),
                mock(X509Certificate.class),
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(123)
            );

            String str = result.toString();

            assertThat(str).contains("verified=true");
            assertThat(str).contains("agentId='test-agent-id'");
            assertThat(str).contains("PT0.123S");
        }

        @Test
        @DisplayName("toString() for failed result includes errors and duration")
        void toStringForFailedResult() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                List.of("error1", "error2"),
                null,
                null,
                mock(X509Certificate.class),
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(456)
            );

            String str = result.toString();

            assertThat(str).contains("verified=false");
            assertThat(str).contains("error1");
            assertThat(str).contains("error2");
            assertThat(str).contains("PT0.456S");
        }
    }
}
