package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScittExpectationTest {

    @Nested
    @DisplayName("Factory method tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("verified() should create expectation with all data")
        void verifiedShouldCreateExpectationWithAllData() {
            List<String> serverCerts = List.of("SHA256:server1", "SHA256:server2");
            List<String> identityCerts = List.of("SHA256:identity1");
            Map<String, String> metadataHashes = Map.of("a2a", "SHA256:metadata1");

            ScittExpectation expectation = ScittExpectation.verified(
                serverCerts, identityCerts, "agent.example.com", "ans://test",
                metadataHashes, null);

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.VERIFIED);
            assertThat(expectation.validServerCertFingerprints()).containsExactlyElementsOf(serverCerts);
            assertThat(expectation.validIdentityCertFingerprints()).containsExactlyElementsOf(identityCerts);
            assertThat(expectation.agentHost()).isEqualTo("agent.example.com");
            assertThat(expectation.ansName()).isEqualTo("ans://test");
            assertThat(expectation.metadataHashes()).isEqualTo(metadataHashes);
            assertThat(expectation.failureReason()).isNull();
            assertThat(expectation.isVerified()).isTrue();
            assertThat(expectation.shouldFail()).isFalse();
        }

        @Test
        @DisplayName("invalidReceipt() should create failure expectation")
        void invalidReceiptShouldCreateFailureExpectation() {
            ScittExpectation expectation = ScittExpectation.invalidReceipt("Bad signature");

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.INVALID_RECEIPT);
            assertThat(expectation.failureReason()).isEqualTo("Bad signature");
            assertThat(expectation.isVerified()).isFalse();
            assertThat(expectation.shouldFail()).isTrue();
            assertThat(expectation.validServerCertFingerprints()).isEmpty();
        }

        @Test
        @DisplayName("invalidToken() should create failure expectation")
        void invalidTokenShouldCreateFailureExpectation() {
            ScittExpectation expectation = ScittExpectation.invalidToken("Malformed token");

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.INVALID_TOKEN);
            assertThat(expectation.failureReason()).isEqualTo("Malformed token");
            assertThat(expectation.shouldFail()).isTrue();
        }

        @Test
        @DisplayName("expired() should create expiry expectation")
        void expiredShouldCreateExpiryExpectation() {
            ScittExpectation expectation = ScittExpectation.expired();

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.TOKEN_EXPIRED);
            assertThat(expectation.failureReason()).isEqualTo("Status token has expired");
            assertThat(expectation.shouldFail()).isTrue();
        }

        @Test
        @DisplayName("revoked() should create revoked expectation")
        void revokedShouldCreateRevokedExpectation() {
            ScittExpectation expectation = ScittExpectation.revoked("ans://revoked.agent");

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.AGENT_REVOKED);
            assertThat(expectation.ansName()).isEqualTo("ans://revoked.agent");
            assertThat(expectation.shouldFail()).isTrue();
        }

        @Test
        @DisplayName("inactive() should create inactive expectation")
        void inactiveShouldCreateInactiveExpectation() {
            ScittExpectation expectation = ScittExpectation.inactive(
                StatusToken.Status.DEPRECATED, "ans://deprecated.agent");

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.AGENT_INACTIVE);
            assertThat(expectation.failureReason()).isEqualTo("Agent status is DEPRECATED");
            assertThat(expectation.shouldFail()).isTrue();
        }

        @Test
        @DisplayName("keyNotFound() should create key not found expectation")
        void keyNotFoundShouldCreateExpectation() {
            ScittExpectation expectation = ScittExpectation.keyNotFound("TL key not found");

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
            assertThat(expectation.failureReason()).isEqualTo("TL key not found");
            assertThat(expectation.shouldFail()).isTrue();
        }

        @Test
        @DisplayName("notPresent() should create not present expectation")
        void notPresentShouldCreateExpectation() {
            ScittExpectation expectation = ScittExpectation.notPresent();

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.NOT_PRESENT);
            assertThat(expectation.isNotPresent()).isTrue();
            assertThat(expectation.shouldFail()).isFalse();  // Not a failure, just fallback needed
        }

        @Test
        @DisplayName("parseError() should create parse error expectation")
        void parseErrorShouldCreateExpectation() {
            ScittExpectation expectation = ScittExpectation.parseError("Invalid CBOR");

            assertThat(expectation.status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
            assertThat(expectation.failureReason()).isEqualTo("Invalid CBOR");
            assertThat(expectation.shouldFail()).isTrue();
        }
    }

    @Nested
    @DisplayName("Status behavior tests")
    class StatusBehaviorTests {

        @Test
        @DisplayName("shouldFail() should return correct values for each status")
        void shouldFailShouldReturnCorrectValues() {
            assertThat(ScittExpectation.verified(List.of(), List.of(), null, null, null, null)
                .shouldFail()).isFalse();
            assertThat(ScittExpectation.notPresent().shouldFail()).isFalse();

            assertThat(ScittExpectation.invalidReceipt("").shouldFail()).isTrue();
            assertThat(ScittExpectation.invalidToken("").shouldFail()).isTrue();
            assertThat(ScittExpectation.expired().shouldFail()).isTrue();
            assertThat(ScittExpectation.revoked("").shouldFail()).isTrue();
            assertThat(ScittExpectation.inactive(StatusToken.Status.EXPIRED, "").shouldFail()).isTrue();
            assertThat(ScittExpectation.keyNotFound("").shouldFail()).isTrue();
            assertThat(ScittExpectation.parseError("").shouldFail()).isTrue();
        }

        @Test
        @DisplayName("isVerified() should only return true for VERIFIED status")
        void isVerifiedShouldOnlyBeTrueForVerifiedStatus() {
            assertThat(ScittExpectation.verified(List.of(), List.of(), null, null, null, null)
                .isVerified()).isTrue();

            assertThat(ScittExpectation.notPresent().isVerified()).isFalse();
            assertThat(ScittExpectation.invalidReceipt("").isVerified()).isFalse();
            assertThat(ScittExpectation.expired().isVerified()).isFalse();
        }

        @Test
        @DisplayName("isNotPresent() should only return true for NOT_PRESENT status")
        void isNotPresentShouldOnlyBeTrueForNotPresentStatus() {
            assertThat(ScittExpectation.notPresent().isNotPresent()).isTrue();

            assertThat(ScittExpectation.verified(List.of(), List.of(), null, null, null, null)
                .isNotPresent()).isFalse();
            assertThat(ScittExpectation.invalidReceipt("").isNotPresent()).isFalse();
        }
    }

    @Nested
    @DisplayName("Defensive copying tests")
    class DefensiveCopyingTests {

        @Test
        @DisplayName("Should defensively copy server cert fingerprints")
        void shouldDefensivelyCopyServerCerts() {
            List<String> mutableList = new java.util.ArrayList<>();
            mutableList.add("cert1");

            ScittExpectation expectation = ScittExpectation.verified(
                mutableList, List.of(), null, null, null, null);

            mutableList.add("cert2");

            assertThat(expectation.validServerCertFingerprints()).containsExactly("cert1");
        }

        @Test
        @DisplayName("Should defensively copy metadata hashes")
        void shouldDefensivelyCopyMetadataHashes() {
            Map<String, String> mutableMap = new java.util.HashMap<>();
            mutableMap.put("key1", "value1");

            ScittExpectation expectation = ScittExpectation.verified(
                List.of(), List.of(), null, null, mutableMap, null);

            mutableMap.put("key2", "value2");

            assertThat(expectation.metadataHashes()).containsOnlyKeys("key1");
        }
    }
}
