package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MerkleProofVerifierTest {

    @Nested
    @DisplayName("hashLeaf() tests")
    class HashLeafTests {

        @Test
        @DisplayName("Should compute correct leaf hash with domain separation")
        void shouldComputeCorrectLeafHash() {
            byte[] data = "test".getBytes(StandardCharsets.UTF_8);
            byte[] hash = MerkleProofVerifier.hashLeaf(data);

            // Should be 32 bytes (SHA-256)
            assertThat(hash).hasSize(32);

            // Different data should produce different hash
            byte[] data2 = "test2".getBytes(StandardCharsets.UTF_8);
            byte[] hash2 = MerkleProofVerifier.hashLeaf(data2);
            assertThat(hash).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should produce consistent hashes")
        void shouldProduceConsistentHashes() {
            byte[] data = "consistent".getBytes(StandardCharsets.UTF_8);
            byte[] hash1 = MerkleProofVerifier.hashLeaf(data);
            byte[] hash2 = MerkleProofVerifier.hashLeaf(data);
            assertThat(hash1).isEqualTo(hash2);
        }

        @Test
        @DisplayName("Leaf hash should differ from raw SHA-256 (domain separation)")
        void leafHashShouldDifferFromRawSha256() throws Exception {
            byte[] data = "test".getBytes(StandardCharsets.UTF_8);
            byte[] leafHash = MerkleProofVerifier.hashLeaf(data);

            // Raw SHA-256 without domain separation prefix
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] rawHash = md.digest(data);

            // Should be different due to 0x00 prefix in leaf hash
            assertThat(leafHash).isNotEqualTo(rawHash);
        }
    }

    @Nested
    @DisplayName("hashNode() tests")
    class HashNodeTests {

        @Test
        @DisplayName("Should compute correct node hash with domain separation")
        void shouldComputeCorrectNodeHash() {
            byte[] left = new byte[32];
            byte[] right = new byte[32];
            Arrays.fill(left, (byte) 0x01);
            Arrays.fill(right, (byte) 0x02);

            byte[] hash = MerkleProofVerifier.hashNode(left, right);
            assertThat(hash).hasSize(32);

            // Different order should produce different hash
            byte[] hashReversed = MerkleProofVerifier.hashNode(right, left);
            assertThat(hash).isNotEqualTo(hashReversed);
        }
    }

    @Nested
    @DisplayName("calculatePathLength() tests")
    class CalculatePathLengthTests {

        @Test
        @DisplayName("Should return 0 for tree size 1")
        void shouldReturn0ForSize1() {
            assertThat(MerkleProofVerifier.calculatePathLength(1)).isEqualTo(0);
        }

        @Test
        @DisplayName("Should return 1 for tree size 2")
        void shouldReturn1ForSize2() {
            assertThat(MerkleProofVerifier.calculatePathLength(2)).isEqualTo(1);
        }

        @Test
        @DisplayName("Should return correct length for power-of-two sizes")
        void shouldReturnCorrectLengthForPowerOfTwo() {
            assertThat(MerkleProofVerifier.calculatePathLength(4)).isEqualTo(2);
            assertThat(MerkleProofVerifier.calculatePathLength(8)).isEqualTo(3);
            assertThat(MerkleProofVerifier.calculatePathLength(16)).isEqualTo(4);
            assertThat(MerkleProofVerifier.calculatePathLength(1024)).isEqualTo(10);
        }

        @Test
        @DisplayName("Should return correct length for non-power-of-two sizes")
        void shouldReturnCorrectLengthForNonPowerOfTwo() {
            assertThat(MerkleProofVerifier.calculatePathLength(3)).isEqualTo(2);
            assertThat(MerkleProofVerifier.calculatePathLength(5)).isEqualTo(3);
            assertThat(MerkleProofVerifier.calculatePathLength(7)).isEqualTo(3);
            assertThat(MerkleProofVerifier.calculatePathLength(100)).isEqualTo(7);
        }
    }

    @Nested
    @DisplayName("verifyInclusion() tests")
    class VerifyInclusionTests {

        @Test
        @DisplayName("Should reject null leaf data")
        void shouldRejectNullLeafData() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(null, 0, 1, List.of(), new byte[32]))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("leafData cannot be null");
        }

        @Test
        @DisplayName("Should reject leaf index >= tree size")
        void shouldRejectInvalidLeafIndex() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(new byte[10], 5, 5, List.of(), new byte[32]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid leaf index");
        }

        @Test
        @DisplayName("Should reject zero tree size")
        void shouldRejectZeroTreeSize() {
            // Note: leaf index validation happens before tree size validation
            // when leaf index >= tree size, so we expect the leaf index error first
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(new byte[10], 0, 0, List.of(), new byte[32]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid leaf index");
        }

        @Test
        @DisplayName("Should reject invalid root hash length")
        void shouldRejectInvalidRootHashLength() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(new byte[10], 0, 1, List.of(), new byte[16]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid expected root hash length");
        }

        @Test
        @DisplayName("Should verify single-element tree")
        void shouldVerifySingleElementTree() throws ScittParseException {
            byte[] leafData = "single leaf".getBytes(StandardCharsets.UTF_8);
            byte[] leafHash = MerkleProofVerifier.hashLeaf(leafData);

            // For a single-element tree, the root hash IS the leaf hash
            boolean valid = MerkleProofVerifier.verifyInclusion(
                leafData, 0, 1, List.of(), leafHash);

            assertThat(valid).isTrue();
        }

        @Test
        @DisplayName("Should reject mismatched root hash")
        void shouldRejectMismatchedRootHash() throws ScittParseException {
            byte[] leafData = "leaf".getBytes(StandardCharsets.UTF_8);
            byte[] wrongRoot = new byte[32];
            Arrays.fill(wrongRoot, (byte) 0xFF);

            boolean valid = MerkleProofVerifier.verifyInclusion(
                leafData, 0, 1, List.of(), wrongRoot);

            assertThat(valid).isFalse();
        }

        @Test
        @DisplayName("Should verify two-element tree")
        void shouldVerifyTwoElementTree() throws ScittParseException {
            // Build a 2-element tree manually
            byte[] leaf0Data = "leaf0".getBytes(StandardCharsets.UTF_8);
            byte[] leaf1Data = "leaf1".getBytes(StandardCharsets.UTF_8);

            byte[] leaf0Hash = MerkleProofVerifier.hashLeaf(leaf0Data);
            byte[] leaf1Hash = MerkleProofVerifier.hashLeaf(leaf1Data);

            // Root = hash(leaf0Hash || leaf1Hash)
            byte[] rootHash = MerkleProofVerifier.hashNode(leaf0Hash, leaf1Hash);

            // Verify leaf0 with leaf1Hash as sibling
            boolean valid0 = MerkleProofVerifier.verifyInclusion(
                leaf0Data, 0, 2, List.of(leaf1Hash), rootHash);
            assertThat(valid0).isTrue();

            // Verify leaf1 with leaf0Hash as sibling
            boolean valid1 = MerkleProofVerifier.verifyInclusion(
                leaf1Data, 1, 2, List.of(leaf0Hash), rootHash);
            assertThat(valid1).isTrue();
        }
    }

    @Nested
    @DisplayName("verifyInclusionWithHash() tests")
    class VerifyInclusionWithHashTests {

        @Test
        @DisplayName("Should reject invalid leaf hash length")
        void shouldRejectInvalidLeafHashLength() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusionWithHash(new byte[16], 0, 1, List.of(), new byte[32]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid leaf hash length");
        }

        @Test
        @DisplayName("Should verify with pre-computed hash")
        void shouldVerifyWithPreComputedHash() throws ScittParseException {
            byte[] leafData = "leaf".getBytes(StandardCharsets.UTF_8);
            byte[] leafHash = MerkleProofVerifier.hashLeaf(leafData);

            boolean valid = MerkleProofVerifier.verifyInclusionWithHash(
                leafHash, 0, 1, List.of(), leafHash);

            assertThat(valid).isTrue();
        }

        @Test
        @DisplayName("Should reject null leaf hash")
        void shouldRejectNullLeafHash() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusionWithHash(null, 0, 1, List.of(), new byte[32]))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("leafHash cannot be null");
        }

        @Test
        @DisplayName("Should reject null hash path")
        void shouldRejectNullHashPath() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusionWithHash(new byte[32], 0, 1, null, new byte[32]))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("hashPath cannot be null");
        }

        @Test
        @DisplayName("Should reject null expected root hash")
        void shouldRejectNullExpectedRootHash() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusionWithHash(new byte[32], 0, 1, List.of(), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("expectedRootHash cannot be null");
        }

        @Test
        @DisplayName("Should reject leaf index >= tree size")
        void shouldRejectInvalidLeafIndex() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusionWithHash(new byte[32], 5, 5, List.of(), new byte[32]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid leaf index");
        }

        @Test
        @DisplayName("Should reject zero tree size")
        void shouldRejectZeroTreeSize() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusionWithHash(new byte[32], 0, 0, List.of(), new byte[32]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid leaf index");
        }

        @Test
        @DisplayName("Should reject invalid expected root hash length")
        void shouldRejectInvalidExpectedRootHashLength() {
            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusionWithHash(new byte[32], 0, 1, List.of(), new byte[16]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid expected root hash length");
        }

        @Test
        @DisplayName("Should verify two-element tree with pre-computed hash")
        void shouldVerifyTwoElementTreeWithPreComputedHash() throws ScittParseException {
            byte[] leaf0Hash = MerkleProofVerifier.hashLeaf("leaf0".getBytes(StandardCharsets.UTF_8));
            byte[] leaf1Hash = MerkleProofVerifier.hashLeaf("leaf1".getBytes(StandardCharsets.UTF_8));
            byte[] rootHash = MerkleProofVerifier.hashNode(leaf0Hash, leaf1Hash);

            boolean valid = MerkleProofVerifier.verifyInclusionWithHash(
                leaf0Hash, 0, 2, List.of(leaf1Hash), rootHash);

            assertThat(valid).isTrue();
        }
    }

    @Nested
    @DisplayName("Hash path validation tests")
    class HashPathValidationTests {

        @Test
        @DisplayName("Should reject hash path too long for tree size")
        void shouldRejectHashPathTooLong() {
            byte[] leafData = "leaf".getBytes(StandardCharsets.UTF_8);
            // For tree size 2, max path length is 1
            List<byte[]> tooLongPath = List.of(new byte[32], new byte[32], new byte[32]);

            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(leafData, 0, 2, tooLongPath, new byte[32]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Hash path too long");
        }

        @Test
        @DisplayName("Should reject null hash in path")
        void shouldRejectNullHashInPath() {
            byte[] leafData = "leaf".getBytes(StandardCharsets.UTF_8);
            List<byte[]> pathWithNull = Arrays.asList(new byte[32], null);

            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(leafData, 0, 4, pathWithNull, new byte[32]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid hash at path index 1");
        }

        @Test
        @DisplayName("Should reject wrong-sized hash in path")
        void shouldRejectWrongSizedHashInPath() {
            byte[] leafData = "leaf".getBytes(StandardCharsets.UTF_8);
            List<byte[]> pathWithWrongSize = List.of(new byte[32], new byte[16]);

            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(leafData, 0, 4, pathWithWrongSize, new byte[32]))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("Invalid hash at path index 1");
        }

        @Test
        @DisplayName("Should reject null hashPath")
        void shouldRejectNullHashPath() {
            byte[] leafData = "leaf".getBytes(StandardCharsets.UTF_8);

            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(leafData, 0, 1, null, new byte[32]))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("hashPath cannot be null");
        }

        @Test
        @DisplayName("Should reject null expectedRootHash")
        void shouldRejectNullExpectedRootHash() {
            byte[] leafData = "leaf".getBytes(StandardCharsets.UTF_8);

            assertThatThrownBy(() ->
                MerkleProofVerifier.verifyInclusion(leafData, 0, 1, List.of(), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("expectedRootHash cannot be null");
        }
    }

    @Nested
    @DisplayName("Tree structure tests")
    class TreeStructureTests {

        @Test
        @DisplayName("Should verify four-element tree (balanced)")
        void shouldVerifyFourElementTree() throws ScittParseException {
            // Tree structure for 4 leaves:
            //           root
            //         /      \
            //      node01   node23
            //      /   \     /   \
            //     L0   L1   L2   L3

            byte[] leaf0Hash = MerkleProofVerifier.hashLeaf("leaf0".getBytes(StandardCharsets.UTF_8));
            byte[] leaf1Hash = MerkleProofVerifier.hashLeaf("leaf1".getBytes(StandardCharsets.UTF_8));
            byte[] leaf2Hash = MerkleProofVerifier.hashLeaf("leaf2".getBytes(StandardCharsets.UTF_8));
            byte[] leaf3Hash = MerkleProofVerifier.hashLeaf("leaf3".getBytes(StandardCharsets.UTF_8));

            byte[] node01Hash = MerkleProofVerifier.hashNode(leaf0Hash, leaf1Hash);
            byte[] node23Hash = MerkleProofVerifier.hashNode(leaf2Hash, leaf3Hash);
            byte[] rootHash = MerkleProofVerifier.hashNode(node01Hash, node23Hash);

            // Verify leaf0 (index=0)
            boolean valid0 = MerkleProofVerifier.verifyInclusionWithHash(
                leaf0Hash, 0, 4, List.of(leaf1Hash, node23Hash), rootHash);
            assertThat(valid0).isTrue();

            // Verify leaf3 (index=3)
            boolean valid3 = MerkleProofVerifier.verifyInclusionWithHash(
                leaf3Hash, 3, 4, List.of(leaf2Hash, node01Hash), rootHash);
            assertThat(valid3).isTrue();
        }
    }

    @Nested
    @DisplayName("calculatePathLength edge cases")
    class CalculatePathLengthEdgeCaseTests {

        @Test
        @DisplayName("Should return 0 for tree size 0")
        void shouldReturn0ForSize0() {
            assertThat(MerkleProofVerifier.calculatePathLength(0)).isEqualTo(0);
        }

        @Test
        @DisplayName("Should handle large tree sizes")
        void shouldHandleLargeTreeSizes() {
            assertThat(MerkleProofVerifier.calculatePathLength(1_000_000)).isEqualTo(20);
            assertThat(MerkleProofVerifier.calculatePathLength(1L << 30)).isEqualTo(30);
        }

        @Test
        @DisplayName("Should handle max practical tree size (2^62)")
        void shouldHandleMaxPracticalTreeSize() {
            // Test a very large but practical tree size (2^62)
            // Path length should be 62
            long largeTreeSize = 1L << 62;
            assertThat(MerkleProofVerifier.calculatePathLength(largeTreeSize)).isEqualTo(62);
        }
    }

    @Nested
    @DisplayName("Utility methods tests")
    class UtilityMethodsTests {

        @Test
        @DisplayName("Should convert hex to bytes")
        void shouldConvertHexToBytes() {
            byte[] bytes = MerkleProofVerifier.hexToBytes("deadbeef");
            assertThat(bytes).containsExactly((byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF);
        }

        @Test
        @DisplayName("Should convert bytes to hex")
        void shouldConvertBytesToHex() {
            byte[] bytes = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
            assertThat(MerkleProofVerifier.bytesToHex(bytes)).isEqualTo("deadbeef");
        }

        @Test
        @DisplayName("Should reject odd-length hex string")
        void shouldRejectOddLengthHex() {
            assertThatThrownBy(() -> MerkleProofVerifier.hexToBytes("abc"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Hex string must have even length");
        }
    }
}
