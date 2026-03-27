package com.godaddy.ans.sdk.transparency.scitt;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * SCITT Receipt - a COSE_Sign1 structure containing a Merkle inclusion proof.
 *
 * <p>A SCITT receipt proves that a specific event was included in the
 * transparency log at a specific tree version. The receipt contains:</p>
 * <ul>
 *   <li>Protected header with TL public key ID and VDS type</li>
 *   <li>Inclusion proof (tree size, leaf index, hash path)</li>
 *   <li>The event payload (JCS-canonicalized)</li>
 *   <li>TL signature over the Sig_structure</li>
 * </ul>
 *
 * @param protectedHeader the parsed COSE protected header
 * @param protectedHeaderBytes raw protected header bytes (for signature verification)
 * @param inclusionProof the Merkle tree inclusion proof
 * @param eventPayload the JCS-canonicalized event data
 * @param signature the TL signature (64 bytes ES256 in IEEE P1363 format)
 */
public record ScittReceipt(
    CoseProtectedHeader protectedHeader,
    byte[] protectedHeaderBytes,
    InclusionProof inclusionProof,
    byte[] eventPayload,
    byte[] signature
) {

    /**
     * Merkle tree inclusion proof extracted from the receipt.
     *
     * @param treeSize the total number of leaves when this leaf was added
     * @param leafIndex the 0-based index of the leaf
     * @param rootHash the root hash at the time of inclusion
     * @param hashPath the sibling hashes from leaf to root
     */
    public record InclusionProof(
        long treeSize,
        long leafIndex,
        byte[] rootHash,
        List<byte[]> hashPath
    ) {
        public InclusionProof {
            hashPath = hashPath != null ? List.copyOf(hashPath) : List.of();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            InclusionProof that = (InclusionProof) o;
            if (treeSize != that.treeSize || leafIndex != that.leafIndex) {
                return false;
            }
            if (!Arrays.equals(rootHash, that.rootHash)) {
                return false;
            }
            if (hashPath.size() != that.hashPath.size()) {
                return false;
            }
            for (int i = 0; i < hashPath.size(); i++) {
                if (!Arrays.equals(hashPath.get(i), that.hashPath.get(i))) {
                    return false;
                }
            }
            return true;
        }

        @Override
        public int hashCode() {
            int result = Long.hashCode(treeSize);
            result = 31 * result + Long.hashCode(leafIndex);
            result = 31 * result + Arrays.hashCode(rootHash);
            for (byte[] hash : hashPath) {
                result = 31 * result + Arrays.hashCode(hash);
            }
            return result;
        }
    }

    /**
     * Parses a SCITT receipt from raw COSE_Sign1 bytes.
     *
     * @param coseBytes the raw COSE_Sign1 bytes
     * @return the parsed receipt
     * @throws ScittParseException if parsing fails
     */
    public static ScittReceipt parse(byte[] coseBytes) throws ScittParseException {
        Objects.requireNonNull(coseBytes, "coseBytes cannot be null");

        CoseSign1Parser.ParsedCoseSign1 parsed = CoseSign1Parser.parse(coseBytes);
        return fromParsedCose(parsed);
    }

    /**
     * Creates a ScittReceipt from an already-parsed COSE_Sign1 structure.
     *
     * @param parsed the parsed COSE_Sign1
     * @return the ScittReceipt
     * @throws ScittParseException if the structure doesn't contain valid receipt data
     */
    public static ScittReceipt fromParsedCose(CoseSign1Parser.ParsedCoseSign1 parsed) throws ScittParseException {
        Objects.requireNonNull(parsed, "parsed cannot be null");

        // Verify VDS indicates RFC 9162 Merkle tree
        CoseProtectedHeader header = parsed.protectedHeader();
        if (!header.isRfc9162MerkleTree()) {
            throw new ScittParseException(
                "Receipt must use VDS=1 (RFC9162_SHA256), got: " + header.vds());
        }

        // Parse inclusion proof from unprotected header (CBORObject passed directly, no round-trip)
        InclusionProof inclusionProof = parseInclusionProof(parsed.unprotectedHeader());

        return new ScittReceipt(
            header,
            parsed.protectedHeaderBytes(),
            inclusionProof,
            parsed.payload(),
            parsed.signature()
        );
    }

    /**
     * Parses the inclusion proof from the unprotected header.
     *
     * <p>The inclusion proof is stored in the unprotected header with label 396
     * per draft-ietf-cose-merkle-tree-proofs. The format is a map with negative
     * integer keys:</p>
     * <ul>
     *   <li>-1: tree_size (required)</li>
     *   <li>-2: leaf_index (required)</li>
     *   <li>-3: hash_path (array of 32-byte hashes, optional)</li>
     *   <li>-4: root_hash (32 bytes, optional)</li>
     * </ul>
     */
    private static InclusionProof parseInclusionProof(CBORObject unprotectedHeader) throws ScittParseException {
        if (unprotectedHeader == null || unprotectedHeader.isNull()
                || unprotectedHeader.getType() != CBORType.Map) {
            throw new ScittParseException("Receipt must have an unprotected header map");
        }

        // Label 396 contains the inclusion proof map
        CBORObject proofObject = unprotectedHeader.get(CBORObject.FromObject(396));
        if (proofObject == null) {
            throw new ScittParseException("Receipt missing inclusion proofs (label 396)");
        }

        // Proof must be a map with negative integer keys
        if (proofObject.getType() != CBORType.Map) {
            throw new ScittParseException("Inclusion proof at label 396 must be a map");
        }

        return parseMapFormatProof(proofObject);
    }

    /**
     * Parses inclusion proof from MAP format with negative integer keys.
     *
     * <p>Expected keys:</p>
     * <ul>
     *   <li>-1: tree_size (required)</li>
     *   <li>-2: leaf_index (required)</li>
     *   <li>-3: hash_path (array of 32-byte hashes, optional)</li>
     *   <li>-4: root_hash (32 bytes, optional)</li>
     * </ul>
     */
    private static InclusionProof parseMapFormatProof(CBORObject proofMap) throws ScittParseException {
        // Extract tree_size (-1) - required
        CBORObject treeSizeObj = proofMap.get(CBORObject.FromObject(-1));
        if (treeSizeObj == null || !treeSizeObj.isNumber()) {
            throw new ScittParseException("Inclusion proof missing required tree_size (key -1)");
        }
        long treeSize = treeSizeObj.AsInt64Value();

        // Extract leaf_index (-2) - required
        CBORObject leafIndexObj = proofMap.get(CBORObject.FromObject(-2));
        if (leafIndexObj == null || !leafIndexObj.isNumber()) {
            throw new ScittParseException("Inclusion proof missing required leaf_index (key -2)");
        }
        long leafIndex = leafIndexObj.AsInt64Value();

        // Extract hash_path (-3) - optional array of 32-byte hashes
        List<byte[]> hashPath = new ArrayList<>();
        CBORObject hashPathObj = proofMap.get(CBORObject.FromObject(-3));
        if (hashPathObj != null && hashPathObj.getType() == CBORType.Array) {
            for (int i = 0; i < hashPathObj.size(); i++) {
                CBORObject element = hashPathObj.get(i);
                if (element.getType() == CBORType.ByteString) {
                    byte[] hash = element.GetByteString();
                    if (hash.length == 32) {
                        hashPath.add(hash);
                    }
                }
            }
        }

        // Extract root_hash (-4) - optional 32-byte hash
        byte[] rootHash = null;
        CBORObject rootHashObj = proofMap.get(CBORObject.FromObject(-4));
        if (rootHashObj != null && rootHashObj.getType() == CBORType.ByteString) {
            byte[] hash = rootHashObj.GetByteString();
            if (hash.length == 32) {
                rootHash = hash;
            }
        }

        return new InclusionProof(treeSize, leafIndex, rootHash, hashPath);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ScittReceipt that = (ScittReceipt) o;
        return Objects.equals(protectedHeader, that.protectedHeader)
            && Arrays.equals(protectedHeaderBytes, that.protectedHeaderBytes)
            && Objects.equals(inclusionProof, that.inclusionProof)
            && Arrays.equals(eventPayload, that.eventPayload)
            && Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(protectedHeader, inclusionProof);
        result = 31 * result + Arrays.hashCode(protectedHeaderBytes);
        result = 31 * result + Arrays.hashCode(eventPayload);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public String toString() {
        return "ScittReceipt{" +
            "protectedHeader=" + protectedHeader +
            ", inclusionProof=" + inclusionProof +
            ", payloadSize=" + (eventPayload != null ? eventPayload.length : 0) +
            '}';
    }
}
