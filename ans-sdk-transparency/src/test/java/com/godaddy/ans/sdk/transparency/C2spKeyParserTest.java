package com.godaddy.ans.sdk.transparency;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class C2spKeyParserTest {

    /**
     * Shared EC key pairs generated once for all tests to keep tests fast and deterministic.
     * secp256r1 (P-256) matches the curve used in production SCITT transparency logs.
     */
    private static KeyPair keyPair1;
    private static KeyPair keyPair2;
    private static KeyPair keyPair3;

    @BeforeAll
    static void generateKeyPairs() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair1 = keyGen.generateKeyPair();
        keyPair2 = keyGen.generateKeyPair();
        keyPair3 = keyGen.generateKeyPair();
    }

    // -----------------------------------------------------------------------
    // Helper utilities
    // -----------------------------------------------------------------------

    /**
     * Builds a canonical C2SP note line: {@code name+keyhash+base64(spkiDer)}.
     * The base64 payload is plain SPKI-DER with no C2SP version prefix.
     */
    private static String c2spLine(String name, String hash, PublicKey key) {
        byte[] spkiDer = key.getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(spkiDer);
        return name + "+" + hash + "+" + base64Key;
    }

    /**
     * Builds a C2SP line with the 0x02 version-byte prefix prepended before the SPKI-DER.
     */
    private static String c2spLineWithVersionPrefix(String name, String hash, PublicKey key) {
        byte[] spkiDer = key.getEncoded();
        byte[] withPrefix = new byte[spkiDer.length + 1];
        withPrefix[0] = 0x02;
        System.arraycopy(spkiDer, 0, withPrefix, 1, spkiDer.length);
        String base64Key = Base64.getEncoder().encodeToString(withPrefix);
        return name + "+" + hash + "+" + base64Key;
    }

    // -----------------------------------------------------------------------
    // parsePublicKeysResponse tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("parsePublicKeysResponse() tests")
    class ParsePublicKeysResponseTests {

        @Test
        @DisplayName("Should throw NullPointerException for null input")
        void shouldThrowNpeForNullInput() {
            assertThatThrownBy(() -> C2spKeyParser.parsePublicKeysResponse(null))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for empty string")
        void shouldThrowForEmptyString() {
            assertThatThrownBy(() -> C2spKeyParser.parsePublicKeysResponse(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Could not parse any public keys from response");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for response with only comments and blank lines")
        void shouldThrowForOnlyCommentsAndBlanks() {
            String response = "# This is a comment\n\n# Another comment\n\n";
            assertThatThrownBy(() -> C2spKeyParser.parsePublicKeysResponse(response))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Could not parse any public keys from response")
                .hasMessageContaining("No parseable key lines found");
        }

        @Test
        @DisplayName("Should return map with one entry for a single valid EC key line")
        void shouldParseSingleValidKeyLine() {
            String line = c2spLine("transparency.ans.godaddy.com", "abcd1234", keyPair1.getPublic());
            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(line);

            assertThat(keys).hasSize(1);
            PublicKey parsedKey = keys.values().iterator().next();
            assertThat(parsedKey.getEncoded()).isEqualTo(keyPair1.getPublic().getEncoded());
        }

        @Test
        @DisplayName("Should return correct count for multiple valid keys")
        void shouldParseMultipleValidKeys() {
            String response = String.join("\n",
                c2spLine("log.example.com", "aabb0011", keyPair1.getPublic()),
                c2spLine("log.example.com", "ccdd2233", keyPair2.getPublic()),
                c2spLine("log.example.com", "eeff4455", keyPair3.getPublic())
            );

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            assertThat(keys).hasSize(3);
        }

        @Test
        @DisplayName("Should map keys by computed hex key ID, not the hash token in the line")
        void shouldKeyByComputedHexKeyId() {
            String response = c2spLine("log.example.com", "ignored-hash", keyPair1.getPublic());
            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            String expectedKeyId = C2spKeyParser.computeHexKeyId(keyPair1.getPublic());
            assertThat(keys).containsKey(expectedKeyId);
        }

        @Test
        @DisplayName("Should skip malformed lines with wrong number of '+' delimiters and still parse valid ones")
        void shouldSkipMalformedLinesAndContinue() {
            String response = String.join("\n",
                "no-plus-signs-at-all",
                "only+one-plus",
                c2spLine("log.example.com", "aabb0011", keyPair1.getPublic()),
                "name+hash+extra+toomanyparts+actually-fine-splits-at-3",
                c2spLine("log.example.com", "ccdd2233", keyPair2.getPublic())
            );

            // Lines with < 3 parts are skipped; line with extra '+' is fine because split limit is 3
            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            // The three-or-more-plus line gets split into exactly 3 parts (base64 segment may contain '+')
            // so it will attempt decoding. The two clean lines are definitely parsed.
            assertThat(keys.size()).isGreaterThanOrEqualTo(2);
            assertThat(keys).containsKey(C2spKeyParser.computeHexKeyId(keyPair1.getPublic()));
            assertThat(keys).containsKey(C2spKeyParser.computeHexKeyId(keyPair2.getPublic()));
        }

        @Test
        @DisplayName("Should skip lines with fewer than 3 '+'-delimited parts")
        void shouldSkipLinesWithTooFewParts() {
            String response = String.join("\n",
                "nodots",
                "only+twoparts",
                c2spLine("log.example.com", "aabb0011", keyPair1.getPublic())
            );

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            assertThat(keys).hasSize(1);
        }

        @Test
        @DisplayName("Should return only first MAX_ROOT_KEYS (20) keys when response exceeds limit")
        void shouldCapAtMaxRootKeys() {
            // Generate 25 distinct key pairs and build a response body
            List<String> lines = new ArrayList<>();
            for (int i = 0; i < 25; i++) {
                try {
                    KeyPairGenerator kg = KeyPairGenerator.getInstance("EC");
                    kg.initialize(new ECGenParameterSpec("secp256r1"));
                    KeyPair kp = kg.generateKeyPair();
                    lines.add(c2spLine("log.example.com", String.format("key%05d", i), kp.getPublic()));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            String response = String.join("\n", lines);

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            assertThat(keys).hasSize(20);
        }

        @Test
        @DisplayName("Should skip lines with invalid base64 and still parse remaining valid lines")
        void shouldSkipInvalidBase64Lines() {
            // An invalid base64 string — contains characters outside the base64 alphabet
            String invalidBase64 = "not!valid!base64!!!";
            String response = String.join("\n",
                "log.example.com+aabb0011+" + invalidBase64,
                c2spLine("log.example.com", "ccdd2233", keyPair1.getPublic())
            );

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            assertThat(keys).hasSize(1);
            assertThat(keys).containsKey(C2spKeyParser.computeHexKeyId(keyPair1.getPublic()));
        }

        @Test
        @DisplayName("Should skip lines with valid base64 that does not decode to a valid EC key")
        void shouldSkipInvalidKeySpec() {
            // Valid base64, but the decoded bytes are not a valid SPKI-DER EC key
            byte[] garbage = new byte[]{0x30, 0x01, 0x02, 0x03, 0x04, 0x05};
            String base64Garbage = Base64.getEncoder().encodeToString(garbage);
            String response = String.join("\n",
                "log.example.com+aabb0011+" + base64Garbage,
                c2spLine("log.example.com", "ccdd2233", keyPair1.getPublic())
            );

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            assertThat(keys).hasSize(1);
            assertThat(keys).containsKey(C2spKeyParser.computeHexKeyId(keyPair1.getPublic()));
        }

        @Test
        @DisplayName("Should correctly strip C2SP version byte (0x02 prefix) before SPKI-DER decoding")
        void shouldStripC2spVersionByte() {
            String line = c2spLineWithVersionPrefix("log.example.com", "aabb0011", keyPair1.getPublic());

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(line);

            assertThat(keys).hasSize(1);
            // The parsed key must be equal to the original key regardless of the prefix
            PublicKey parsedKey = keys.values().iterator().next();
            assertThat(parsedKey.getEncoded()).isEqualTo(keyPair1.getPublic().getEncoded());
        }

        @Test
        @DisplayName("Should produce the same key ID whether the 0x02 prefix is present or absent")
        void shouldProduceSameKeyIdWithAndWithoutVersionPrefix() {
            String withPrefix = c2spLineWithVersionPrefix("log.example.com", "aabb0011", keyPair1.getPublic());
            String withoutPrefix = c2spLine("log.example.com", "aabb0011", keyPair1.getPublic());

            Map<String, PublicKey> keysWithPrefix = C2spKeyParser.parsePublicKeysResponse(withPrefix);
            Map<String, PublicKey> keysWithoutPrefix = C2spKeyParser.parsePublicKeysResponse(withoutPrefix);

            assertThat(keysWithPrefix.keySet()).isEqualTo(keysWithoutPrefix.keySet());
        }

        @Test
        @DisplayName("Should ignore comment lines starting with '#'")
        void shouldIgnoreCommentLines() {
            String response = String.join("\n",
                "# This is a header comment",
                c2spLine("log.example.com", "aabb0011", keyPair1.getPublic()),
                "# Another comment mid-file",
                c2spLine("log.example.com", "ccdd2233", keyPair2.getPublic())
            );

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            assertThat(keys).hasSize(2);
        }

        @Test
        @DisplayName("Should ignore blank lines between key entries")
        void shouldIgnoreBlankLines() {
            String response = String.join("\n",
                "",
                c2spLine("log.example.com", "aabb0011", keyPair1.getPublic()),
                "",
                "",
                c2spLine("log.example.com", "ccdd2233", keyPair2.getPublic()),
                ""
            );

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            assertThat(keys).hasSize(2);
        }

        @Test
        @DisplayName("Should silently skip duplicate key IDs and keep the first occurrence")
        void shouldSkipDuplicateKeyIds() {
            // Same key, two different C2SP lines — same hex key ID
            String response = String.join("\n",
                c2spLine("log.example.com", "aabb0011", keyPair1.getPublic()),
                c2spLine("log2.example.com", "aabb0011", keyPair1.getPublic())
            );

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            // Only one entry for the duplicate key
            assertThat(keys).hasSize(1);
        }

        @Test
        @DisplayName("Should return an immutable map")
        void shouldReturnImmutableMap() {
            String response = c2spLine("log.example.com", "aabb0011", keyPair1.getPublic());
            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response);

            assertThatThrownBy(() -> keys.put("newkey", keyPair1.getPublic()))
                .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("Should include parse failure details in exception message when all lines are malformed")
        void shouldIncludeParseErrorDetailsInException() {
            String response = String.join("\n",
                "nodots",
                "only+twoparts"
            );

            assertThatThrownBy(() -> C2spKeyParser.parsePublicKeysResponse(response))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Parse attempts failed");
        }

        @Test
        @DisplayName("Should trim whitespace from key lines before parsing")
        void shouldTrimWhitespaceFromLines() {
            String line = "   " + c2spLine("log.example.com", "aabb0011", keyPair1.getPublic()) + "   ";
            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(line);

            assertThat(keys).hasSize(1);
        }

        @Test
        @DisplayName("Should trim whitespace from base64 key segment before decoding")
        void shouldTrimWhitespaceFromBase64Segment() {
            byte[] spkiDer = keyPair1.getPublic().getEncoded();
            String base64Key = "  " + Base64.getEncoder().encodeToString(spkiDer) + "  ";
            String line = "log.example.com+aabb0011+" + base64Key;

            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(line);

            assertThat(keys).hasSize(1);
        }
    }

    // -----------------------------------------------------------------------
    // computeHexKeyId tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("computeHexKeyId() tests")
    class ComputeHexKeyIdTests {

        @Test
        @DisplayName("Should produce exactly 8 hexadecimal characters")
        void shouldProduceExactly8HexChars() {
            String keyId = C2spKeyParser.computeHexKeyId(keyPair1.getPublic());

            assertThat(keyId).hasSize(8);
            assertThat(keyId).matches("[0-9a-f]{8}");
        }

        @Test
        @DisplayName("Should produce lowercase hex characters")
        void shouldProduceLowercaseHex() {
            String keyId = C2spKeyParser.computeHexKeyId(keyPair1.getPublic());

            assertThat(keyId).isEqualTo(keyId.toLowerCase());
        }

        @Test
        @DisplayName("Should be consistent for the same key on repeated calls")
        void shouldBeConsistentForSameKey() {
            String keyId1 = C2spKeyParser.computeHexKeyId(keyPair1.getPublic());
            String keyId2 = C2spKeyParser.computeHexKeyId(keyPair1.getPublic());

            assertThat(keyId1).isEqualTo(keyId2);
        }

        @Test
        @DisplayName("Should produce different IDs for different keys")
        void shouldProduceDifferentIdsForDifferentKeys() {
            String keyId1 = C2spKeyParser.computeHexKeyId(keyPair1.getPublic());
            String keyId2 = C2spKeyParser.computeHexKeyId(keyPair2.getPublic());
            String keyId3 = C2spKeyParser.computeHexKeyId(keyPair3.getPublic());

            assertThat(keyId1).isNotEqualTo(keyId2);
            assertThat(keyId1).isNotEqualTo(keyId3);
            assertThat(keyId2).isNotEqualTo(keyId3);
        }

        @Test
        @DisplayName("Should derive key ID from the first 4 bytes of SHA-256 of SPKI-DER")
        void shouldDeriveKeyIdFromFirst4BytesOfSha256() throws Exception {
            PublicKey key = keyPair1.getPublic();
            byte[] spkiDer = key.getEncoded();

            // Manually compute expected key ID
            java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(spkiDer);
            String expectedHex = String.format("%02x%02x%02x%02x",
                hash[0] & 0xFF, hash[1] & 0xFF, hash[2] & 0xFF, hash[3] & 0xFF);

            String actualKeyId = C2spKeyParser.computeHexKeyId(key);

            assertThat(actualKeyId).isEqualTo(expectedHex);
        }

        @Test
        @DisplayName("Should match the key ID used as the map key in parsePublicKeysResponse")
        void shouldMatchMapKeyFromParseResponse() {
            String line = c2spLine("log.example.com", "aabb0011", keyPair2.getPublic());
            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(line);

            String expectedKeyId = C2spKeyParser.computeHexKeyId(keyPair2.getPublic());

            assertThat(keys).containsKey(expectedKeyId);
        }

        @Test
        @DisplayName("Should produce identical key ID for key decoded from C2SP-prefixed base64")
        void shouldProduceSameKeyIdAfterVersionPrefixStripping() {
            // Compute expected ID from raw key
            String expectedKeyId = C2spKeyParser.computeHexKeyId(keyPair1.getPublic());

            // Parse from C2SP-prefixed line and extract the resulting key ID
            String prefixedLine = c2spLineWithVersionPrefix("log.example.com", "aabb0011", keyPair1.getPublic());
            Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(prefixedLine);

            assertThat(keys).containsKey(expectedKeyId);
        }
    }
}
