package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MetadataHashVerifierTest {

    @Nested
    @DisplayName("verify() tests")
    class VerifyTests {

        @Test
        @DisplayName("Should reject null metadata bytes")
        void shouldRejectNullMetadataBytes() {
            assertThatThrownBy(() -> MetadataHashVerifier.verify(null, "SHA256:abc"))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("metadataBytes cannot be null");
        }

        @Test
        @DisplayName("Should reject null expected hash")
        void shouldRejectNullExpectedHash() {
            assertThatThrownBy(() -> MetadataHashVerifier.verify(new byte[10], null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("expectedHash cannot be null");
        }

        @Test
        @DisplayName("Should reject invalid hash format")
        void shouldRejectInvalidHashFormat() {
            byte[] data = "test".getBytes(StandardCharsets.UTF_8);

            assertThat(MetadataHashVerifier.verify(data, "invalid")).isFalse();
            assertThat(MetadataHashVerifier.verify(data, "SHA256:abc")).isFalse();  // Too short
            assertThat(MetadataHashVerifier.verify(data, "MD5:0123456789abcdef0123456789abcdef")).isFalse();
        }

        @Test
        @DisplayName("Should verify matching hash")
        void shouldVerifyMatchingHash() {
            byte[] data = "test metadata content".getBytes(StandardCharsets.UTF_8);
            String hash = MetadataHashVerifier.computeHash(data);

            assertThat(MetadataHashVerifier.verify(data, hash)).isTrue();
        }

        @Test
        @DisplayName("Should reject mismatched hash")
        void shouldRejectMismatchedHash() {
            byte[] data = "test metadata".getBytes(StandardCharsets.UTF_8);
            String wrongHash = "SHA256:0000000000000000000000000000000000000000000000000000000000000000";

            assertThat(MetadataHashVerifier.verify(data, wrongHash)).isFalse();
        }

        @Test
        @DisplayName("Should be case insensitive for hash prefix")
        void shouldBeCaseInsensitiveForPrefix() {
            byte[] data = "test".getBytes(StandardCharsets.UTF_8);
            String hash = MetadataHashVerifier.computeHash(data);
            String lowerHash = hash.toLowerCase();
            String upperHash = hash.toUpperCase();

            assertThat(MetadataHashVerifier.verify(data, lowerHash)).isTrue();
            assertThat(MetadataHashVerifier.verify(data, upperHash)).isTrue();
        }
    }

    @Nested
    @DisplayName("computeHash() tests")
    class ComputeHashTests {

        @Test
        @DisplayName("Should reject null input")
        void shouldRejectNullInput() {
            assertThatThrownBy(() -> MetadataHashVerifier.computeHash(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("metadataBytes cannot be null");
        }

        @Test
        @DisplayName("Should compute hash with correct format")
        void shouldComputeHashWithCorrectFormat() {
            byte[] data = "test".getBytes(StandardCharsets.UTF_8);
            String hash = MetadataHashVerifier.computeHash(data);

            assertThat(hash).startsWith("SHA256:");
            assertThat(hash).hasSize(7 + 64);  // "SHA256:" + 64 hex chars
        }

        @Test
        @DisplayName("Should produce consistent hashes")
        void shouldProduceConsistentHashes() {
            byte[] data = "consistent data".getBytes(StandardCharsets.UTF_8);

            assertThat(MetadataHashVerifier.computeHash(data))
                .isEqualTo(MetadataHashVerifier.computeHash(data));
        }

        @Test
        @DisplayName("Should produce different hashes for different data")
        void shouldProduceDifferentHashes() {
            String hash1 = MetadataHashVerifier.computeHash("data1".getBytes());
            String hash2 = MetadataHashVerifier.computeHash("data2".getBytes());

            assertThat(hash1).isNotEqualTo(hash2);
        }
    }

    @Nested
    @DisplayName("isValidHashFormat() tests")
    class IsValidHashFormatTests {

        @Test
        @DisplayName("Should accept valid hash format")
        void shouldAcceptValidFormat() {
            String validHash = "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            assertThat(MetadataHashVerifier.isValidHashFormat(validHash)).isTrue();
        }

        @Test
        @DisplayName("Should accept uppercase hex")
        void shouldAcceptUppercaseHex() {
            String validHash = "SHA256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
            assertThat(MetadataHashVerifier.isValidHashFormat(validHash)).isTrue();
        }

        @Test
        @DisplayName("Should reject null")
        void shouldRejectNull() {
            assertThat(MetadataHashVerifier.isValidHashFormat(null)).isFalse();
        }

        @Test
        @DisplayName("Should reject wrong prefix")
        void shouldRejectWrongPrefix() {
            assertThat(MetadataHashVerifier.isValidHashFormat("MD5:abc")).isFalse();
            assertThat(MetadataHashVerifier.isValidHashFormat("sha256:abc")).isFalse();
        }

        @Test
        @DisplayName("Should reject wrong length")
        void shouldRejectWrongLength() {
            assertThat(MetadataHashVerifier.isValidHashFormat("SHA256:abc")).isFalse();
            assertThat(MetadataHashVerifier.isValidHashFormat("SHA256:")).isFalse();
        }

        @Test
        @DisplayName("Should reject non-hex characters")
        void shouldRejectNonHexCharacters() {
            String invalidHash = "SHA256:ghijklmnopqrstuvwxyz0123456789abcdef0123456789abcdef01234567";
            assertThat(MetadataHashVerifier.isValidHashFormat(invalidHash)).isFalse();
        }
    }

    @Nested
    @DisplayName("extractHex() tests")
    class ExtractHexTests {

        @Test
        @DisplayName("Should extract hex portion")
        void shouldExtractHexPortion() {
            String hash = "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            String hex = MetadataHashVerifier.extractHex(hash);

            assertThat(hex).isEqualTo("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        }

        @Test
        @DisplayName("Should return lowercase hex")
        void shouldReturnLowercaseHex() {
            String hash = "SHA256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
            String hex = MetadataHashVerifier.extractHex(hash);

            assertThat(hex).isEqualTo("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        }

        @Test
        @DisplayName("Should return null for invalid format")
        void shouldReturnNullForInvalidFormat() {
            assertThat(MetadataHashVerifier.extractHex(null)).isNull();
            assertThat(MetadataHashVerifier.extractHex("invalid")).isNull();
            assertThat(MetadataHashVerifier.extractHex("SHA256:abc")).isNull();
        }
    }
}
