package com.godaddy.ans.sdk.transparency.scitt;

import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultScittHeaderProviderTest {

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create provider with no arguments")
        void shouldCreateWithNoArguments() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();
            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should create provider with receipt and token bytes")
        void shouldCreateWithReceiptAndToken() {
            byte[] receipt = {0x01, 0x02, 0x03};
            byte[] token = {0x04, 0x05, 0x06};

            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider(receipt, token);
            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should create provider with null values")
        void shouldCreateWithNullValues() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider(null, null);
            assertThat(provider).isNotNull();
        }
    }

    @Nested
    @DisplayName("Builder tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build empty provider")
        void shouldBuildEmptyProvider() {
            DefaultScittHeaderProvider provider = DefaultScittHeaderProvider.builder().build();
            assertThat(provider).isNotNull();
            assertThat(provider.getOutgoingHeaders()).isEmpty();
        }

        @Test
        @DisplayName("Should build provider with receipt")
        void shouldBuildProviderWithReceipt() {
            byte[] receipt = {0x01, 0x02, 0x03};

            DefaultScittHeaderProvider provider = DefaultScittHeaderProvider.builder()
                .receipt(receipt)
                .build();

            Map<String, String> headers = provider.getOutgoingHeaders();
            assertThat(headers).containsKey(ScittHeaders.SCITT_RECEIPT_HEADER);
        }

        @Test
        @DisplayName("Should build provider with status token")
        void shouldBuildProviderWithStatusToken() {
            byte[] token = {0x01, 0x02, 0x03};

            DefaultScittHeaderProvider provider = DefaultScittHeaderProvider.builder()
                .statusToken(token)
                .build();

            Map<String, String> headers = provider.getOutgoingHeaders();
            assertThat(headers).containsKey(ScittHeaders.STATUS_TOKEN_HEADER);
        }

        @Test
        @DisplayName("Should build provider with both artifacts")
        void shouldBuildProviderWithBoth() {
            byte[] receipt = {0x01, 0x02, 0x03};
            byte[] token = {0x04, 0x05, 0x06};

            DefaultScittHeaderProvider provider = DefaultScittHeaderProvider.builder()
                .receipt(receipt)
                .statusToken(token)
                .build();

            Map<String, String> headers = provider.getOutgoingHeaders();
            assertThat(headers).hasSize(2);
            assertThat(headers).containsKey(ScittHeaders.SCITT_RECEIPT_HEADER);
            assertThat(headers).containsKey(ScittHeaders.STATUS_TOKEN_HEADER);
        }
    }

    @Nested
    @DisplayName("getOutgoingHeaders() tests")
    class GetOutgoingHeadersTests {

        @Test
        @DisplayName("Should return empty map when no artifacts")
        void shouldReturnEmptyMapWhenNoArtifacts() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();

            Map<String, String> headers = provider.getOutgoingHeaders();

            assertThat(headers).isEmpty();
        }

        @Test
        @DisplayName("Should Base64 encode receipt")
        void shouldBase64EncodeReceipt() {
            byte[] receipt = {0x01, 0x02, 0x03};
            String expectedBase64 = Base64.getEncoder().encodeToString(receipt);

            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider(receipt, null);

            Map<String, String> headers = provider.getOutgoingHeaders();

            assertThat(headers.get(ScittHeaders.SCITT_RECEIPT_HEADER)).isEqualTo(expectedBase64);
        }

        @Test
        @DisplayName("Should Base64 encode status token")
        void shouldBase64EncodeStatusToken() {
            byte[] token = {0x04, 0x05, 0x06};
            String expectedBase64 = Base64.getEncoder().encodeToString(token);

            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider(null, token);

            Map<String, String> headers = provider.getOutgoingHeaders();

            assertThat(headers.get(ScittHeaders.STATUS_TOKEN_HEADER)).isEqualTo(expectedBase64);
        }

        @Test
        @DisplayName("Should return immutable map")
        void shouldReturnImmutableMap() {
            byte[] receipt = {0x01, 0x02, 0x03};
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider(receipt, null);

            Map<String, String> headers = provider.getOutgoingHeaders();

            assertThatThrownBy(() -> headers.put("new-key", "value"))
                .isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Nested
    @DisplayName("extractArtifacts() tests")
    class ExtractArtifactsTests {

        @Test
        @DisplayName("Should reject null headers")
        void shouldRejectNullHeaders() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();

            assertThatThrownBy(() -> provider.extractArtifacts(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("headers cannot be null");
        }

        @Test
        @DisplayName("Should return empty when no SCITT headers")
        void shouldReturnEmptyWhenNoScittHeaders() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();

            Optional<ScittHeaderProvider.ScittArtifacts> result =
                provider.extractArtifacts(Map.of("Content-Type", "application/json"));

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should extract valid status token")
        void shouldExtractValidStatusToken() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();
            byte[] tokenBytes = createValidStatusTokenBytes();
            String base64Token = Base64.getEncoder().encodeToString(tokenBytes);

            Map<String, String> headers = Map.of(ScittHeaders.STATUS_TOKEN_HEADER, base64Token);

            Optional<ScittHeaderProvider.ScittArtifacts> result = provider.extractArtifacts(headers);

            assertThat(result).isPresent();
            assertThat(result.get().statusToken()).isNotNull();
            assertThat(result.get().statusToken().agentId()).isEqualTo("test-agent");
        }

        @Test
        @DisplayName("Should extract valid receipt")
        void shouldExtractValidReceipt() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();
            byte[] receiptBytes = createValidReceiptBytes();
            String base64Receipt = Base64.getEncoder().encodeToString(receiptBytes);

            Map<String, String> headers = Map.of(ScittHeaders.SCITT_RECEIPT_HEADER, base64Receipt);

            Optional<ScittHeaderProvider.ScittArtifacts> result = provider.extractArtifacts(headers);

            assertThat(result).isPresent();
            assertThat(result.get().receipt()).isNotNull();
        }

        @Test
        @DisplayName("Should extract both receipt and token")
        void shouldExtractBothArtifacts() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();
            byte[] receiptBytes = createValidReceiptBytes();
            byte[] tokenBytes = createValidStatusTokenBytes();

            Map<String, String> headers = new HashMap<>();
            headers.put(ScittHeaders.SCITT_RECEIPT_HEADER, Base64.getEncoder().encodeToString(receiptBytes));
            headers.put(ScittHeaders.STATUS_TOKEN_HEADER, Base64.getEncoder().encodeToString(tokenBytes));

            Optional<ScittHeaderProvider.ScittArtifacts> result = provider.extractArtifacts(headers);

            assertThat(result).isPresent();
            assertThat(result.get().receipt()).isNotNull();
            assertThat(result.get().statusToken()).isNotNull();
            assertThat(result.get().isComplete()).isTrue();
            assertThat(result.get().isPresent()).isTrue();
        }

        @Test
        @DisplayName("Should throw when headers present but invalid Base64")
        void shouldThrowOnInvalidBase64() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();

            Map<String, String> headers = Map.of(ScittHeaders.STATUS_TOKEN_HEADER, "not-valid-base64!!!");

            // Headers present but parse failed should throw, not return empty
            // This allows callers to distinguish "no headers" from "headers present but malformed"
            assertThatThrownBy(() -> provider.extractArtifacts(headers))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SCITT headers present but failed to parse")
                .hasMessageContaining("Invalid Base64");
        }

        @Test
        @DisplayName("Should throw when headers present but invalid CBOR")
        void shouldThrowOnInvalidCbor() {
            DefaultScittHeaderProvider provider = new DefaultScittHeaderProvider();
            byte[] invalidCbor = {0x01, 0x02, 0x03};

            Map<String, String> headers = Map.of(
                ScittHeaders.STATUS_TOKEN_HEADER, Base64.getEncoder().encodeToString(invalidCbor));

            // Headers present but parse failed should throw, not return empty
            assertThatThrownBy(() -> provider.extractArtifacts(headers))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SCITT headers present but failed to parse");
        }
    }

    @Nested
    @DisplayName("ScittArtifacts tests")
    class ScittArtifactsTests {

        @Test
        @DisplayName("isComplete should return true when both present")
        void isCompleteShouldReturnTrueWhenBothPresent() {
            ScittReceipt receipt = createMockReceipt();
            StatusToken token = createMockToken();

            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token, new byte[0], new byte[0]);

            assertThat(artifacts.isComplete()).isTrue();
        }

        @Test
        @DisplayName("isComplete should return false when receipt missing")
        void isCompleteShouldReturnFalseWhenReceiptMissing() {
            StatusToken token = createMockToken();

            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(null, token, null, new byte[0]);

            assertThat(artifacts.isComplete()).isFalse();
        }

        @Test
        @DisplayName("isComplete should return false when token missing")
        void isCompleteShouldReturnFalseWhenTokenMissing() {
            ScittReceipt receipt = createMockReceipt();

            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, null, new byte[0], null);

            assertThat(artifacts.isComplete()).isFalse();
        }

        @Test
        @DisplayName("isPresent should return true when at least one present")
        void isPresentShouldReturnTrueWhenAtLeastOnePresent() {
            ScittReceipt receipt = createMockReceipt();

            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, null, new byte[0], null);

            assertThat(artifacts.isPresent()).isTrue();
        }

        @Test
        @DisplayName("isPresent should return false when both null")
        void isPresentShouldReturnFalseWhenBothNull() {
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(null, null, null, null);

            assertThat(artifacts.isPresent()).isFalse();
        }
    }

    // Helper methods

    private byte[] createValidStatusTokenBytes() {
        long now = Instant.now().getEpochSecond();

        // Use integer keys: 1=agent_id, 2=status, 3=iat, 4=exp
        CBORObject payload = CBORObject.NewMap();
        payload.Add(1, "test-agent");  // agent_id
        payload.Add(2, "ACTIVE");      // status
        payload.Add(3, now);           // iat
        payload.Add(4, now + 3600);    // exp

        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(1, -7);  // alg = ES256
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        CBORObject array = CBORObject.NewArray();
        array.Add(protectedBytes);
        array.Add(CBORObject.NewMap());
        array.Add(payload.EncodeToBytes());
        array.Add(new byte[64]);  // signature
        CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

        return tagged.EncodeToBytes();
    }

    private byte[] createValidReceiptBytes() {
        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(1, -7);  // alg = ES256
        protectedHeader.Add(395, 1);  // vds = RFC9162_SHA256
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        // Create unprotected header with inclusion proof (MAP format)
        CBORObject inclusionProofMap = CBORObject.NewMap();
        inclusionProofMap.Add(-1, 1L);  // tree_size
        inclusionProofMap.Add(-2, 0L);  // leaf_index
        inclusionProofMap.Add(-3, CBORObject.NewArray());  // empty hash_path
        inclusionProofMap.Add(-4, CBORObject.FromObject(new byte[32]));  // root_hash

        CBORObject unprotectedHeader = CBORObject.NewMap();
        unprotectedHeader.Add(396, inclusionProofMap);

        CBORObject array = CBORObject.NewArray();
        array.Add(protectedBytes);
        array.Add(unprotectedHeader);
        array.Add("test-payload".getBytes());
        array.Add(new byte[64]);  // signature
        CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

        return tagged.EncodeToBytes();
    }

    private ScittReceipt createMockReceipt() {
        CoseProtectedHeader header = new CoseProtectedHeader(-7, new byte[4], 1, null, null);
        ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, new byte[32], java.util.List.of());
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
            java.util.List.of(),
            java.util.List.of(),
            java.util.Map.of(),
            null,
            null,
            null,
            null
        );
    }
}