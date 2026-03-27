package com.godaddy.ans.sdk.transparency.scitt;

import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScittReceiptTest {

    @Nested
    @DisplayName("parse() tests")
    class ParseTests {

        @Test
        @DisplayName("Should reject null input")
        void shouldRejectNullInput() {
            assertThatThrownBy(() -> ScittReceipt.parse(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("coseBytes cannot be null");
        }

        @Test
        @DisplayName("Should reject receipt without VDS")
        void shouldRejectReceiptWithoutVds() {
            // Create COSE_Sign1 without VDS (395) in protected header
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256, but no VDS
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject unprotectedHeader = createValidUnprotectedHeader();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> ScittReceipt.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("VDS=1");
        }

        @Test
        @DisplayName("Should reject receipt with wrong VDS value")
        void shouldRejectReceiptWithWrongVds() {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);  // alg = ES256
            protectedHeader.Add(395, 2);  // Wrong VDS value
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            CBORObject unprotectedHeader = createValidUnprotectedHeader();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> ScittReceipt.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("VDS=1");
        }

        @Test
        @DisplayName("Should reject receipt without proofs")
        void shouldRejectReceiptWithoutProofs() {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            // Empty unprotected header (no proofs)
            CBORObject emptyUnprotected = CBORObject.NewMap();

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(emptyUnprotected);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> ScittReceipt.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("inclusion proofs");
        }

        @Test
        @DisplayName("Should parse valid receipt with RFC 9162 proof format")
        void shouldParseValidReceiptWithRfc9162Format() throws ScittParseException {
            byte[] receiptBytes = createValidReceiptWithRfc9162Proof();

            ScittReceipt receipt = ScittReceipt.parse(receiptBytes);

            assertThat(receipt).isNotNull();
            assertThat(receipt.protectedHeader()).isNotNull();
            assertThat(receipt.protectedHeader().algorithm()).isEqualTo(-7);
            assertThat(receipt.inclusionProof()).isNotNull();
            assertThat(receipt.eventPayload()).isNotNull();
            assertThat(receipt.signature()).hasSize(64);
        }

        @Test
        @DisplayName("Should parse receipt with tree size and leaf index")
        void shouldParseReceiptWithTreeSizeAndLeafIndex() throws ScittParseException {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            // Create proof with tree_size=100, leaf_index=42 using MAP format
            CBORObject inclusionProofMap = CBORObject.NewMap();
            inclusionProofMap.Add(-1, 100L);  // tree_size
            inclusionProofMap.Add(-2, 42L);   // leaf_index
            inclusionProofMap.Add(-3, CBORObject.NewArray());  // empty hash_path
            inclusionProofMap.Add(-4, CBORObject.FromObject(new byte[32]));  // root_hash

            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, inclusionProofMap);

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            ScittReceipt receipt = ScittReceipt.parse(tagged.EncodeToBytes());

            assertThat(receipt.inclusionProof().treeSize()).isEqualTo(100);
            assertThat(receipt.inclusionProof().leafIndex()).isEqualTo(42);
        }

        @Test
        @DisplayName("Should parse receipt with hash path")
        void shouldParseReceiptWithHashPath() throws ScittParseException {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            byte[] hash1 = new byte[32];
            byte[] hash2 = new byte[32];
            hash1[0] = 0x01;
            hash2[0] = 0x02;

            // MAP format with hash path array at key -3
            CBORObject hashPathArray = CBORObject.NewArray();
            hashPathArray.Add(CBORObject.FromObject(hash1));
            hashPathArray.Add(CBORObject.FromObject(hash2));

            CBORObject inclusionProofMap = CBORObject.NewMap();
            inclusionProofMap.Add(-1, 4L);   // tree_size
            inclusionProofMap.Add(-2, 2L);   // leaf_index
            inclusionProofMap.Add(-3, hashPathArray);  // hash_path array
            inclusionProofMap.Add(-4, CBORObject.FromObject(new byte[32]));  // root_hash

            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, inclusionProofMap);

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            ScittReceipt receipt = ScittReceipt.parse(tagged.EncodeToBytes());

            assertThat(receipt.inclusionProof().hashPath()).hasSize(2);
        }
    }

    @Nested
    @DisplayName("InclusionProof tests")
    class InclusionProofTests {

        @Test
        @DisplayName("Should create inclusion proof with null hashPath")
        void shouldCreateInclusionProofWithNullHashPath() {
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], null);

            assertThat(proof.hashPath()).isEmpty();
        }

        @Test
        @DisplayName("Should defensively copy hashPath")
        void shouldDefensivelyCopyHashPath() {
            List<byte[]> originalPath = new java.util.ArrayList<>();
            originalPath.add(new byte[32]);

            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], originalPath);

            // Original list modification should not affect proof
            originalPath.add(new byte[32]);

            assertThat(proof.hashPath()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("equals() and hashCode() tests")
    class EqualsHashCodeTests {

        @Test
        @DisplayName("Should be equal for same values")
        void shouldBeEqualForSameValues() {
            ScittReceipt receipt1 = createBasicReceipt();
            ScittReceipt receipt2 = createBasicReceipt();

            assertThat(receipt1).isEqualTo(receipt2);
            assertThat(receipt1.hashCode()).isEqualTo(receipt2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            ScittReceipt receipt = createBasicReceipt();
            assertThat(receipt).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            ScittReceipt receipt = createBasicReceipt();
            assertThat(receipt).isEqualTo(receipt);
        }

        @Test
        @DisplayName("toString should contain useful info")
        void toStringShouldContainUsefulInfo() {
            ScittReceipt receipt = createBasicReceipt();
            String str = receipt.toString();

            assertThat(str).contains("ScittReceipt");
        }

        @Test
        @DisplayName("Should not be equal when protected header differs")
        void shouldNotBeEqualWhenProtectedHeaderDiffers() {
            CoseProtectedHeader header1 = new CoseProtectedHeader(-7, new byte[4], 1, null, null);
            CoseProtectedHeader header2 = new CoseProtectedHeader(-35, new byte[4], 1, null, null); // Different alg
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, new byte[32], List.of());

            ScittReceipt receipt1 = new ScittReceipt(header1, new byte[10], proof, "payload".getBytes(), new byte[64]);
            ScittReceipt receipt2 = new ScittReceipt(header2, new byte[10], proof, "payload".getBytes(), new byte[64]);

            assertThat(receipt1).isNotEqualTo(receipt2);
        }

        @Test
        @DisplayName("Should not be equal when signature differs")
        void shouldNotBeEqualWhenSignatureDiffers() {
            CoseProtectedHeader header = new CoseProtectedHeader(-7, new byte[4], 1, null, null);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, new byte[32], List.of());

            byte[] sig1 = new byte[64];
            byte[] sig2 = new byte[64];
            sig2[0] = 1; // Different signature

            ScittReceipt receipt1 = new ScittReceipt(header, new byte[10], proof, "payload".getBytes(), sig1);
            ScittReceipt receipt2 = new ScittReceipt(header, new byte[10], proof, "payload".getBytes(), sig2);

            assertThat(receipt1).isNotEqualTo(receipt2);
        }

        @Test
        @DisplayName("Should not be equal when payload differs")
        void shouldNotBeEqualWhenPayloadDiffers() {
            CoseProtectedHeader header = new CoseProtectedHeader(-7, new byte[4], 1, null, null);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, new byte[32], List.of());

            ScittReceipt receipt1 = new ScittReceipt(header, new byte[10], proof, "payload1".getBytes(), new byte[64]);
            ScittReceipt receipt2 = new ScittReceipt(header, new byte[10], proof, "payload2".getBytes(), new byte[64]);

            assertThat(receipt1).isNotEqualTo(receipt2);
        }
    }

    @Nested
    @DisplayName("InclusionProof equals tests")
    class InclusionProofEqualsTests {

        @Test
        @DisplayName("Should not be equal when tree size differs")
        void shouldNotBeEqualWhenTreeSizeDiffers() {
            ScittReceipt.InclusionProof proof1 = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], List.of());
            ScittReceipt.InclusionProof proof2 = new ScittReceipt.InclusionProof(
                20, 5, new byte[32], List.of());

            assertThat(proof1).isNotEqualTo(proof2);
        }

        @Test
        @DisplayName("Should not be equal when leaf index differs")
        void shouldNotBeEqualWhenLeafIndexDiffers() {
            ScittReceipt.InclusionProof proof1 = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], List.of());
            ScittReceipt.InclusionProof proof2 = new ScittReceipt.InclusionProof(
                10, 7, new byte[32], List.of());

            assertThat(proof1).isNotEqualTo(proof2);
        }

        @Test
        @DisplayName("Should not be equal when root hash differs")
        void shouldNotBeEqualWhenRootHashDiffers() {
            byte[] hash1 = new byte[32];
            byte[] hash2 = new byte[32];
            hash2[0] = 1;

            ScittReceipt.InclusionProof proof1 = new ScittReceipt.InclusionProof(
                10, 5, hash1, List.of());
            ScittReceipt.InclusionProof proof2 = new ScittReceipt.InclusionProof(
                10, 5, hash2, List.of());

            assertThat(proof1).isNotEqualTo(proof2);
        }

        @Test
        @DisplayName("Should not be equal when hash path length differs")
        void shouldNotBeEqualWhenHashPathLengthDiffers() {
            List<byte[]> path1 = List.of(new byte[32]);
            List<byte[]> path2 = List.of(new byte[32], new byte[32]);

            ScittReceipt.InclusionProof proof1 = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], path1);
            ScittReceipt.InclusionProof proof2 = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], path2);

            assertThat(proof1).isNotEqualTo(proof2);
        }

        @Test
        @DisplayName("Should not be equal when hash path content differs")
        void shouldNotBeEqualWhenHashPathContentDiffers() {
            byte[] pathHash1 = new byte[32];
            byte[] pathHash2 = new byte[32];
            pathHash2[0] = 1;

            ScittReceipt.InclusionProof proof1 = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], List.of(pathHash1));
            ScittReceipt.InclusionProof proof2 = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], List.of(pathHash2));

            assertThat(proof1).isNotEqualTo(proof2);
        }

        @Test
        @DisplayName("Should have different hash codes for different proofs")
        void shouldHaveDifferentHashCodesForDifferentProofs() {
            ScittReceipt.InclusionProof proof1 = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], List.of());
            ScittReceipt.InclusionProof proof2 = new ScittReceipt.InclusionProof(
                20, 5, new byte[32], List.of());

            assertThat(proof1.hashCode()).isNotEqualTo(proof2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                10, 5, new byte[32], List.of());

            assertThat(proof).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("Parsing edge cases")
    class ParsingEdgeCaseTests {

        @Test
        @DisplayName("Should reject receipt with empty inclusion proof map")
        void shouldRejectReceiptWithEmptyInclusionProofMap() {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            // Empty inclusion proof map (missing required keys)
            CBORObject emptyProofMap = CBORObject.NewMap();
            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, emptyProofMap);

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> ScittReceipt.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("tree_size");
        }

        @Test
        @DisplayName("Should reject receipt with non-map at label 396")
        void shouldRejectReceiptWithNonMapAtLabel396() {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            // Label 396 with string instead of map
            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, "not a map");

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> ScittReceipt.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("must be a map");
        }

        @Test
        @DisplayName("Should reject receipt with missing leaf_index key")
        void shouldRejectReceiptWithMissingLeafIndex() {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            // Inclusion proof map with only tree_size (missing leaf_index)
            CBORObject inclusionProofMap = CBORObject.NewMap();
            inclusionProofMap.Add(-1, 1L);  // tree_size only
            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, inclusionProofMap);

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            assertThatThrownBy(() -> ScittReceipt.parse(tagged.EncodeToBytes()))
                .isInstanceOf(ScittParseException.class)
                .hasMessageContaining("leaf_index");
        }

        @Test
        @DisplayName("Should parse receipt with root hash at key -4")
        void shouldParseReceiptWithRootHash() throws ScittParseException {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            byte[] rootHash = new byte[32];
            rootHash[0] = 0x01;

            // MAP format with root hash at key -4
            CBORObject inclusionProofMap = CBORObject.NewMap();
            inclusionProofMap.Add(-1, 100L);  // tree_size
            inclusionProofMap.Add(-2, 42L);   // leaf_index
            inclusionProofMap.Add(-3, CBORObject.NewArray());  // empty hash_path
            inclusionProofMap.Add(-4, CBORObject.FromObject(rootHash));  // root_hash

            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, inclusionProofMap);

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            ScittReceipt receipt = ScittReceipt.parse(tagged.EncodeToBytes());

            assertThat(receipt.inclusionProof().treeSize()).isEqualTo(100);
            assertThat(receipt.inclusionProof().leafIndex()).isEqualTo(42);
            assertThat(receipt.inclusionProof().rootHash()).isEqualTo(rootHash);
        }

        @Test
        @DisplayName("Should parse receipt with multiple hashes in path")
        void shouldParseReceiptWithMultipleHashesInPath() throws ScittParseException {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            byte[] hash1 = new byte[32];
            byte[] hash2 = new byte[32];
            hash1[0] = 0x11;
            hash2[0] = 0x22;

            // Hash path array at key -3
            CBORObject hashPathArray = CBORObject.NewArray();
            hashPathArray.Add(CBORObject.FromObject(hash1));
            hashPathArray.Add(CBORObject.FromObject(hash2));

            CBORObject inclusionProofMap = CBORObject.NewMap();
            inclusionProofMap.Add(-1, 8L);   // tree_size
            inclusionProofMap.Add(-2, 3L);   // leaf_index
            inclusionProofMap.Add(-3, hashPathArray);  // hash_path array
            inclusionProofMap.Add(-4, CBORObject.FromObject(new byte[32]));  // root_hash

            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, inclusionProofMap);

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            ScittReceipt receipt = ScittReceipt.parse(tagged.EncodeToBytes());

            assertThat(receipt.inclusionProof().hashPath()).hasSize(2);
        }

        @Test
        @DisplayName("Should parse receipt with minimal required fields")
        void shouldParseReceiptWithMinimalRequiredFields() throws ScittParseException {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            // Minimal map with just tree_size and leaf_index
            CBORObject inclusionProofMap = CBORObject.NewMap();
            inclusionProofMap.Add(-1, 10L);  // tree_size
            inclusionProofMap.Add(-2, 5L);   // leaf_index

            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, inclusionProofMap);

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            ScittReceipt receipt = ScittReceipt.parse(tagged.EncodeToBytes());

            assertThat(receipt.inclusionProof().treeSize()).isEqualTo(10);
            assertThat(receipt.inclusionProof().leafIndex()).isEqualTo(5);
            assertThat(receipt.inclusionProof().hashPath()).isEmpty();
        }

        @Test
        @DisplayName("Should skip non-32-byte entries in hash path")
        void shouldSkipNon32ByteEntriesInHashPath() throws ScittParseException {
            CBORObject protectedHeader = CBORObject.NewMap();
            protectedHeader.Add(1, -7);
            protectedHeader.Add(395, 1);
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            // Hash path with mixed valid and invalid entries
            CBORObject hashPathArray = CBORObject.NewArray();
            hashPathArray.Add(CBORObject.FromObject(new byte[32]));  // valid 32-byte hash
            hashPathArray.Add(CBORObject.FromObject(new byte[16]));  // invalid 16-byte (skipped)

            CBORObject inclusionProofMap = CBORObject.NewMap();
            inclusionProofMap.Add(-1, 4L);  // tree_size
            inclusionProofMap.Add(-2, 1L);  // leaf_index
            inclusionProofMap.Add(-3, hashPathArray);  // hash_path with mixed sizes
            inclusionProofMap.Add(-4, CBORObject.FromObject(new byte[32]));  // root_hash

            CBORObject unprotectedHeader = CBORObject.NewMap();
            unprotectedHeader.Add(396, inclusionProofMap);

            CBORObject array = CBORObject.NewArray();
            array.Add(protectedBytes);
            array.Add(unprotectedHeader);
            array.Add("payload".getBytes());
            array.Add(new byte[64]);
            CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

            ScittReceipt receipt = ScittReceipt.parse(tagged.EncodeToBytes());

            // Only the valid 32-byte hash should be included
            assertThat(receipt.inclusionProof().hashPath()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("toString() tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include protectedHeader info")
        void shouldIncludeProtectedHeaderInfo() {
            ScittReceipt receipt = createBasicReceipt();
            String str = receipt.toString();

            assertThat(str).contains("protectedHeader");
        }

        @Test
        @DisplayName("Should include inclusionProof info")
        void shouldIncludeInclusionProofInfo() {
            ScittReceipt receipt = createBasicReceipt();
            String str = receipt.toString();

            assertThat(str).contains("inclusionProof");
        }

        @Test
        @DisplayName("Should include payload size")
        void shouldIncludePayloadSize() {
            ScittReceipt receipt = createBasicReceipt();
            String str = receipt.toString();

            assertThat(str).contains("payloadSize");
        }

        @Test
        @DisplayName("Should handle null payload in toString")
        void shouldHandleNullPayloadInToString() {
            CoseProtectedHeader header = new CoseProtectedHeader(-7, new byte[4], 1, null, null);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, new byte[32], List.of());
            ScittReceipt receipt = new ScittReceipt(header, new byte[10], proof, null, new byte[64]);

            String str = receipt.toString();
            assertThat(str).contains("payloadSize=0");
        }
    }

    @Nested
    @DisplayName("fromParsedCose() tests")
    class FromParsedCoseTests {

        @Test
        @DisplayName("Should reject null parsed input")
        void shouldRejectNullParsedInput() {
            assertThatThrownBy(() -> ScittReceipt.fromParsedCose(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("parsed cannot be null");
        }
    }

    @Nested
    @DisplayName("hashCode() tests")
    class HashCodeTests {

        @Test
        @DisplayName("Should have consistent hashCode")
        void shouldHaveConsistentHashCode() {
            ScittReceipt receipt = createBasicReceipt();
            int hash1 = receipt.hashCode();
            int hash2 = receipt.hashCode();

            assertThat(hash1).isEqualTo(hash2);
        }

        @Test
        @DisplayName("Should have same hashCode for equal receipts")
        void shouldHaveSameHashCodeForEqualReceipts() {
            ScittReceipt receipt1 = createBasicReceipt();
            ScittReceipt receipt2 = createBasicReceipt();

            assertThat(receipt1.hashCode()).isEqualTo(receipt2.hashCode());
        }
    }

    // Helper methods

    private byte[] createValidReceiptWithRfc9162Proof() {
        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(1, -7);  // alg = ES256
        protectedHeader.Add(395, 1);  // vds = RFC9162_SHA256
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        CBORObject unprotectedHeader = createValidUnprotectedHeader();

        CBORObject array = CBORObject.NewArray();
        array.Add(protectedBytes);
        array.Add(unprotectedHeader);
        array.Add("test-payload".getBytes());
        array.Add(new byte[64]);  // signature
        CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

        return tagged.EncodeToBytes();
    }

    /**
     * Creates a valid unprotected header using MAP format at label 396.
     * This matches the Go server format with negative integer keys:
     * -1: tree_size, -2: leaf_index, -3: hash_path, -4: root_hash
     */
    private CBORObject createValidUnprotectedHeader() {
        CBORObject inclusionProofMap = CBORObject.NewMap();
        inclusionProofMap.Add(-1, 1L);  // tree_size
        inclusionProofMap.Add(-2, 0L);  // leaf_index
        inclusionProofMap.Add(-3, CBORObject.NewArray());  // empty hash_path
        inclusionProofMap.Add(-4, CBORObject.FromObject(new byte[32]));  // root_hash

        CBORObject unprotectedHeader = CBORObject.NewMap();
        unprotectedHeader.Add(396, inclusionProofMap);  // proofs label

        return unprotectedHeader;
    }

    private ScittReceipt createBasicReceipt() {
        CoseProtectedHeader header = new CoseProtectedHeader(-7, new byte[4], 1, null, null);
        ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, new byte[32], List.of());
        return new ScittReceipt(header, new byte[10], proof, "payload".getBytes(), new byte[64]);
    }
}