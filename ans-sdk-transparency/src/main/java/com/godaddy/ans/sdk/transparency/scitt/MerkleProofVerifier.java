package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.crypto.CryptoCache;

import java.security.MessageDigest;
import java.util.List;
import java.util.Objects;

/**
 * Verifies RFC 9162 Merkle tree inclusion proofs.
 *
 * <p>This implementation follows RFC 9162 Section 2.1 for computing
 * Merkle tree hashes and verifying inclusion proofs.</p>
 *
 * <p><b>Security considerations:</b></p>
 * <ul>
 *   <li>Uses unsigned arithmetic for tree_size and leaf_index comparisons</li>
 *   <li>Validates hash path length against tree size</li>
 *   <li>Uses constant-time comparison for root hash verification</li>
 * </ul>
 */
public final class MerkleProofVerifier {

    /**
     * Domain separation byte for leaf nodes (RFC 9162).
     */
    private static final byte LEAF_PREFIX = 0x00;

    /**
     * Domain separation byte for interior nodes (RFC 9162).
     */
    private static final byte NODE_PREFIX = 0x01;

    /**
     * SHA-256 hash output size in bytes.
     */
    private static final int HASH_SIZE = 32;

    private MerkleProofVerifier() {
        // Utility class
    }

    /**
     * Verifies a Merkle inclusion proof.
     *
     * @param leafData the leaf data (will be hashed with leaf prefix)
     * @param leafIndex the 0-based index of the leaf in the tree
     * @param treeSize the total number of leaves in the tree
     * @param hashPath the proof path (sibling hashes from leaf to root)
     * @param expectedRootHash the expected root hash
     * @return true if the proof is valid
     * @throws ScittParseException if verification fails due to invalid parameters
     */
    public static boolean verifyInclusion(
            byte[] leafData,
            long leafIndex,
            long treeSize,
            List<byte[]> hashPath,
            byte[] expectedRootHash) throws ScittParseException {

        Objects.requireNonNull(leafData, "leafData cannot be null");
        Objects.requireNonNull(hashPath, "hashPath cannot be null");
        Objects.requireNonNull(expectedRootHash, "expectedRootHash cannot be null");

        // Validate parameters using unsigned comparison
        if (Long.compareUnsigned(leafIndex, treeSize) >= 0) {
            throw new ScittParseException(
                "Invalid leaf index: " + Long.toUnsignedString(leafIndex) +
                " >= tree size " + Long.toUnsignedString(treeSize));
        }

        if (treeSize == 0) {
            throw new ScittParseException("Tree size cannot be zero");
        }

        // Validate hash path length
        int expectedPathLength = calculatePathLength(treeSize);
        if (hashPath.size() > expectedPathLength) {
            throw new ScittParseException(
                "Hash path too long: " + hashPath.size() +
                " > expected max " + expectedPathLength + " for tree size " + treeSize);
        }

        // Validate all hashes in path are correct size
        for (int i = 0; i < hashPath.size(); i++) {
            if (hashPath.get(i) == null || hashPath.get(i).length != HASH_SIZE) {
                throw new ScittParseException(
                    "Invalid hash at path index " + i + ": expected " + HASH_SIZE + " bytes");
            }
        }

        if (expectedRootHash.length != HASH_SIZE) {
            throw new ScittParseException(
                "Invalid expected root hash length: " + expectedRootHash.length);
        }

        // Compute leaf hash
        byte[] computedHash = hashLeaf(leafData);

        // Walk up the tree using the inclusion proof
        computedHash = computeRootFromPath(computedHash, leafIndex, treeSize, hashPath);

        // SECURITY: Use constant-time comparison
        return MessageDigest.isEqual(computedHash, expectedRootHash);
    }

    /**
     * Verifies a Merkle inclusion proof where the leaf hash is already computed.
     *
     * @param leafHash the pre-computed leaf hash
     * @param leafIndex the 0-based index of the leaf in the tree
     * @param treeSize the total number of leaves in the tree
     * @param hashPath the proof path (sibling hashes from leaf to root)
     * @param expectedRootHash the expected root hash
     * @return true if the proof is valid
     * @throws ScittParseException if verification fails
     */
    public static boolean verifyInclusionWithHash(
            byte[] leafHash,
            long leafIndex,
            long treeSize,
            List<byte[]> hashPath,
            byte[] expectedRootHash) throws ScittParseException {

        Objects.requireNonNull(leafHash, "leafHash cannot be null");
        Objects.requireNonNull(hashPath, "hashPath cannot be null");
        Objects.requireNonNull(expectedRootHash, "expectedRootHash cannot be null");

        if (leafHash.length != HASH_SIZE) {
            throw new ScittParseException("Invalid leaf hash length: " + leafHash.length);
        }

        if (Long.compareUnsigned(leafIndex, treeSize) >= 0) {
            throw new ScittParseException(
                "Invalid leaf index: " + Long.toUnsignedString(leafIndex) +
                " >= tree size " + Long.toUnsignedString(treeSize));
        }

        if (treeSize == 0) {
            throw new ScittParseException("Tree size cannot be zero");
        }

        if (expectedRootHash.length != HASH_SIZE) {
            throw new ScittParseException(
                "Invalid expected root hash length: " + expectedRootHash.length);
        }

        // Walk up the tree
        byte[] computedHash = computeRootFromPath(leafHash, leafIndex, treeSize, hashPath);

        // SECURITY: Use constant-time comparison
        return MessageDigest.isEqual(computedHash, expectedRootHash);
    }

    /**
     * Computes the root hash from a leaf and inclusion proof path.
     *
     * <p>Implements the RFC 9162 algorithm for computing the root from
     * an inclusion proof (Section 2.1.3.2):</p>
     *
     * <pre>
     * fn = leaf_index
     * sn = tree_size - 1
     * r  = leaf_hash
     * for each p[i] in path:
     *     if LSB(fn) == 1 OR fn == sn:
     *         r = SHA-256(0x01 || p[i] || r)
     *         while fn is not zero and LSB(fn) == 0:
     *             fn = fn >> 1
     *             sn = sn >> 1
     *     else:
     *         r = SHA-256(0x01 || r || p[i])
     *     fn = fn >> 1
     *     sn = sn >> 1
     * verify fn == 0
     * </pre>
     */
    private static byte[] computeRootFromPath(
            byte[] leafHash,
            long leafIndex,
            long treeSize,
            List<byte[]> hashPath) throws ScittParseException {

        byte[] r = leafHash.clone();
        long fn = leafIndex;
        long sn = treeSize - 1;

        for (byte[] p : hashPath) {
            if ((fn & 1) == 1 || fn == sn) {
                // Left sibling: r = H(0x01 || p || r)
                r = hashNode(p, r);
                // Remove consecutive right-side path bits
                while (fn != 0 && (fn & 1) == 0) {
                    fn >>>= 1;
                    sn >>>= 1;
                }
            } else {
                // Right sibling: r = H(0x01 || r || p)
                r = hashNode(r, p);
            }
            fn >>>= 1;
            sn >>>= 1;
        }

        if (fn != 0) {
            throw new ScittParseException(
                "Proof path too short: fn=" + fn + " after consuming all path elements");
        }

        return r;
    }

    /**
     * Computes the hash of a leaf node.
     *
     * <p>Per RFC 9162: MTH({d(0)}) = SHA-256(0x00 || d(0))</p>
     *
     * @param data the leaf data
     * @return the leaf hash
     */
    public static byte[] hashLeaf(byte[] data) {
        byte[] prefixed = new byte[1 + data.length];
        prefixed[0] = LEAF_PREFIX;
        System.arraycopy(data, 0, prefixed, 1, data.length);
        return CryptoCache.sha256(prefixed);
    }

    /**
     * Computes the hash of an interior node.
     *
     * <p>Per RFC 9162: MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))</p>
     *
     * @param left the left child hash
     * @param right the right child hash
     * @return the node hash
     */
    public static byte[] hashNode(byte[] left, byte[] right) {
        byte[] combined = new byte[1 + HASH_SIZE + HASH_SIZE];
        combined[0] = NODE_PREFIX;
        System.arraycopy(left, 0, combined, 1, HASH_SIZE);
        System.arraycopy(right, 0, combined, 1 + HASH_SIZE, HASH_SIZE);
        return CryptoCache.sha256(combined);
    }

    /**
     * Calculates the expected maximum path length for a tree of the given size.
     *
     * <p>For a tree with n leaves, the path length is ceil(log2(n)).</p>
     *
     * @param treeSize the number of leaves
     * @return the maximum path length
     */
    public static int calculatePathLength(long treeSize) {
        if (treeSize <= 1) {
            return 0;
        }
        // Use bit manipulation for ceiling of log2
        return 64 - Long.numberOfLeadingZeros(treeSize - 1);
    }

    /**
     * Converts a hex string to bytes.
     *
     * @param hex the hex string
     * @return the byte array
     * @throws IllegalArgumentException if hex is null or has odd length
     */
    public static byte[] hexToBytes(String hex) {
        return CertificateUtils.hexToBytes(hex);
    }

    /**
     * Converts bytes to a hex string.
     *
     * @param bytes the byte array
     * @return the hex string (lowercase)
     */
    public static String bytesToHex(byte[] bytes) {
        return CertificateUtils.bytesToHex(bytes);
    }
}