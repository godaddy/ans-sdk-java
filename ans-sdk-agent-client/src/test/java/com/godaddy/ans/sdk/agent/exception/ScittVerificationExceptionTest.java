package com.godaddy.ans.sdk.agent.exception;

import com.godaddy.ans.sdk.agent.exception.ScittVerificationException.FailureType;
import com.godaddy.ans.sdk.agent.exception.TrustValidationException.ValidationFailureReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for ScittVerificationException.
 */
class ScittVerificationExceptionTest {

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create exception with message and failure type")
        void shouldCreateWithMessageAndFailureType() {
            ScittVerificationException ex = new ScittVerificationException(
                "Receipt signature invalid", FailureType.INVALID_SIGNATURE);

            assertThat(ex.getMessage()).isEqualTo("Receipt signature invalid");
            assertThat(ex.getFailureType()).isEqualTo(FailureType.INVALID_SIGNATURE);
            assertThat(ex.getCause()).isNull();
        }

        @Test
        @DisplayName("Should create exception with message, cause, and failure type")
        void shouldCreateWithMessageCauseAndFailureType() {
            RuntimeException cause = new RuntimeException("Underlying error");
            ScittVerificationException ex = new ScittVerificationException(
                "Parse failed", cause, FailureType.PARSE_ERROR);

            assertThat(ex.getMessage()).isEqualTo("Parse failed");
            assertThat(ex.getCause()).isEqualTo(cause);
            assertThat(ex.getFailureType()).isEqualTo(FailureType.PARSE_ERROR);
        }

        @Test
        @DisplayName("Should create exception with message, certificate subject, and failure type")
        void shouldCreateWithMessageCertSubjectAndFailureType() {
            ScittVerificationException ex = new ScittVerificationException(
                "Fingerprint mismatch", "CN=test.example.com", FailureType.FINGERPRINT_MISMATCH);

            assertThat(ex.getMessage()).isEqualTo("Fingerprint mismatch");
            assertThat(ex.getFailureType()).isEqualTo(FailureType.FINGERPRINT_MISMATCH);
            assertThat(ex.getCertificateSubject()).isEqualTo("CN=test.example.com");
        }
    }

    @Nested
    @DisplayName("FailureType mapping tests")
    class FailureTypeMappingTests {

        @Test
        @DisplayName("PARSE_ERROR maps to UNKNOWN")
        void parseErrorMapsToUnknown() {
            ScittVerificationException ex = new ScittVerificationException(
                "Parse error", FailureType.PARSE_ERROR);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.UNKNOWN);
        }

        @Test
        @DisplayName("INVALID_ALGORITHM maps to CHAIN_VALIDATION_FAILED")
        void invalidAlgorithmMapsToChainValidationFailed() {
            ScittVerificationException ex = new ScittVerificationException(
                "Invalid algorithm", FailureType.INVALID_ALGORITHM);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.CHAIN_VALIDATION_FAILED);
        }

        @Test
        @DisplayName("INVALID_SIGNATURE maps to CHAIN_VALIDATION_FAILED")
        void invalidSignatureMapsToChainValidationFailed() {
            ScittVerificationException ex = new ScittVerificationException(
                "Invalid signature", FailureType.INVALID_SIGNATURE);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.CHAIN_VALIDATION_FAILED);
        }

        @Test
        @DisplayName("MERKLE_PROOF_INVALID maps to CHAIN_VALIDATION_FAILED")
        void merkleProofInvalidMapsToChainValidationFailed() {
            ScittVerificationException ex = new ScittVerificationException(
                "Invalid Merkle proof", FailureType.MERKLE_PROOF_INVALID);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.CHAIN_VALIDATION_FAILED);
        }

        @Test
        @DisplayName("TOKEN_EXPIRED maps to EXPIRED")
        void tokenExpiredMapsToExpired() {
            ScittVerificationException ex = new ScittVerificationException(
                "Token expired", FailureType.TOKEN_EXPIRED);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.EXPIRED);
        }

        @Test
        @DisplayName("KEY_NOT_FOUND maps to TRUST_BUNDLE_LOAD_FAILED")
        void keyNotFoundMapsToTrustBundleLoadFailed() {
            ScittVerificationException ex = new ScittVerificationException(
                "Key not found", FailureType.KEY_NOT_FOUND);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.TRUST_BUNDLE_LOAD_FAILED);
        }

        @Test
        @DisplayName("FINGERPRINT_MISMATCH maps to CHAIN_VALIDATION_FAILED")
        void fingerprintMismatchMapsToChainValidationFailed() {
            ScittVerificationException ex = new ScittVerificationException(
                "Fingerprint mismatch", FailureType.FINGERPRINT_MISMATCH);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.CHAIN_VALIDATION_FAILED);
        }

        @Test
        @DisplayName("AGENT_REVOKED maps to REVOKED")
        void agentRevokedMapsToRevoked() {
            ScittVerificationException ex = new ScittVerificationException(
                "Agent revoked", FailureType.AGENT_REVOKED);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.REVOKED);
        }

        @Test
        @DisplayName("AGENT_INACTIVE maps to UNKNOWN")
        void agentInactiveMapsToUnknown() {
            ScittVerificationException ex = new ScittVerificationException(
                "Agent inactive", FailureType.AGENT_INACTIVE);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.UNKNOWN);
        }

        @Test
        @DisplayName("VERIFICATION_ERROR maps to UNKNOWN")
        void verificationErrorMapsToUnknown() {
            ScittVerificationException ex = new ScittVerificationException(
                "Verification error", FailureType.VERIFICATION_ERROR);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.UNKNOWN);
        }

        @Test
        @DisplayName("Null failure type maps to UNKNOWN")
        void nullFailureTypeMapsToUnknown() {
            ScittVerificationException ex = new ScittVerificationException(
                "Unknown error", (FailureType) null);
            assertThat(ex.getReason()).isEqualTo(ValidationFailureReason.UNKNOWN);
            assertThat(ex.getFailureType()).isNull();
        }
    }

    @Nested
    @DisplayName("FailureType enum tests")
    class FailureTypeEnumTests {

        @ParameterizedTest
        @EnumSource(FailureType.class)
        @DisplayName("All failure types should be valid")
        void allFailureTypesShouldBeValid(FailureType type) {
            assertThat(type).isNotNull();
            assertThat(type.name()).isNotBlank();
        }

        @Test
        @DisplayName("Should have expected number of failure types")
        void shouldHaveExpectedNumberOfFailureTypes() {
            // 11 types: HEADERS_NOT_PRESENT, PARSE_ERROR, INVALID_ALGORITHM, INVALID_SIGNATURE,
            // MERKLE_PROOF_INVALID, TOKEN_EXPIRED, KEY_NOT_FOUND, FINGERPRINT_MISMATCH,
            // AGENT_REVOKED, AGENT_INACTIVE, VERIFICATION_ERROR
            assertThat(FailureType.values()).hasSize(11);
        }

        @Test
        @DisplayName("Should resolve all failure type names")
        void shouldResolveAllFailureTypeNames() {
            assertThat(FailureType.valueOf("HEADERS_NOT_PRESENT")).isEqualTo(FailureType.HEADERS_NOT_PRESENT);
            assertThat(FailureType.valueOf("PARSE_ERROR")).isEqualTo(FailureType.PARSE_ERROR);
            assertThat(FailureType.valueOf("INVALID_ALGORITHM")).isEqualTo(FailureType.INVALID_ALGORITHM);
            assertThat(FailureType.valueOf("INVALID_SIGNATURE")).isEqualTo(FailureType.INVALID_SIGNATURE);
            assertThat(FailureType.valueOf("MERKLE_PROOF_INVALID")).isEqualTo(FailureType.MERKLE_PROOF_INVALID);
            assertThat(FailureType.valueOf("TOKEN_EXPIRED")).isEqualTo(FailureType.TOKEN_EXPIRED);
            assertThat(FailureType.valueOf("KEY_NOT_FOUND")).isEqualTo(FailureType.KEY_NOT_FOUND);
            assertThat(FailureType.valueOf("FINGERPRINT_MISMATCH")).isEqualTo(FailureType.FINGERPRINT_MISMATCH);
            assertThat(FailureType.valueOf("AGENT_REVOKED")).isEqualTo(FailureType.AGENT_REVOKED);
            assertThat(FailureType.valueOf("AGENT_INACTIVE")).isEqualTo(FailureType.AGENT_INACTIVE);
            assertThat(FailureType.valueOf("VERIFICATION_ERROR")).isEqualTo(FailureType.VERIFICATION_ERROR);
        }
    }

    @Nested
    @DisplayName("Inheritance tests")
    class InheritanceTests {

        @Test
        @DisplayName("Should extend TrustValidationException")
        void shouldExtendTrustValidationException() {
            ScittVerificationException ex = new ScittVerificationException(
                "Test", FailureType.PARSE_ERROR);
            assertThat(ex).isInstanceOf(TrustValidationException.class);
        }

        @Test
        @DisplayName("Should be throwable as Exception")
        void shouldBeThrowableAsException() {
            ScittVerificationException ex = new ScittVerificationException(
                "Test", FailureType.PARSE_ERROR);
            assertThat(ex).isInstanceOf(Exception.class);
        }
    }
}