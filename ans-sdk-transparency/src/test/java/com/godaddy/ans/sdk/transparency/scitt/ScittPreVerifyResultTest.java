package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScittPreVerifyResultTest {

    @Nested
    @DisplayName("Factory methods tests")
    class FactoryMethodsTests {

        @Test
        @DisplayName("notPresent() should create result with isPresent=false")
        void notPresentShouldCreateResultWithIsPresentFalse() {
            ScittPreVerifyResult result = ScittPreVerifyResult.notPresent();

            assertThat(result.isPresent()).isFalse();
            assertThat(result.expectation()).isNotNull();
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.NOT_PRESENT);
            assertThat(result.receipt()).isNull();
            assertThat(result.statusToken()).isNull();
        }

        @Test
        @DisplayName("parseError() should create result with isPresent=true")
        void parseErrorShouldCreateResultWithIsPresentTrue() {
            ScittPreVerifyResult result = ScittPreVerifyResult.parseError("Test error");

            assertThat(result.isPresent()).isTrue();
            assertThat(result.expectation()).isNotNull();
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
            assertThat(result.expectation().failureReason()).contains("Test error");
            assertThat(result.receipt()).isNull();
            assertThat(result.statusToken()).isNull();
        }

        @Test
        @DisplayName("verified() should create result with all components")
        void verifiedShouldCreateResultWithAllComponents() {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("fp1"), List.of("fp2"), "host", "ans.test", Map.of(), null);
            ScittReceipt receipt = createMockReceipt();
            StatusToken token = createMockToken();

            ScittPreVerifyResult result = ScittPreVerifyResult.verified(expectation, receipt, token);

            assertThat(result.isPresent()).isTrue();
            assertThat(result.expectation()).isEqualTo(expectation);
            assertThat(result.expectation().isVerified()).isTrue();
            assertThat(result.receipt()).isEqualTo(receipt);
            assertThat(result.statusToken()).isEqualTo(token);
        }
    }

    @Nested
    @DisplayName("Record accessor tests")
    class RecordAccessorTests {

        @Test
        @DisplayName("Should access all record components")
        void shouldAccessAllRecordComponents() {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("fp1"), List.of(), "host", "ans.test", Map.of(), null);
            ScittReceipt receipt = createMockReceipt();
            StatusToken token = createMockToken();

            ScittPreVerifyResult result = new ScittPreVerifyResult(expectation, receipt, token, true);

            assertThat(result.expectation()).isEqualTo(expectation);
            assertThat(result.receipt()).isEqualTo(receipt);
            assertThat(result.statusToken()).isEqualTo(token);
            assertThat(result.isPresent()).isTrue();
        }

        @Test
        @DisplayName("Should handle null components")
        void shouldHandleNullComponents() {
            ScittPreVerifyResult result = new ScittPreVerifyResult(null, null, null, false);

            assertThat(result.expectation()).isNull();
            assertThat(result.receipt()).isNull();
            assertThat(result.statusToken()).isNull();
            assertThat(result.isPresent()).isFalse();
        }
    }

    private ScittReceipt createMockReceipt() {
        CoseProtectedHeader header = new CoseProtectedHeader(-7, new byte[4], 1, null, null);
        ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, new byte[32], List.of());
        return new ScittReceipt(header, new byte[10], proof, "payload".getBytes(), new byte[64]);
    }

    private StatusToken createMockToken() {
        return new StatusToken(
            "test-agent",
            StatusToken.Status.ACTIVE,
            Instant.now(),
            Instant.now().plusSeconds(3600),
            "test.ans",
            "agent.example.com",
            List.of(),
            List.of(),
            Map.of(),
            null,
            null,
            null,
            null
        );
    }
}