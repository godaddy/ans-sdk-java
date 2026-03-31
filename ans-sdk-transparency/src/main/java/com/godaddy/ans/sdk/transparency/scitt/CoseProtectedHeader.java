package com.godaddy.ans.sdk.transparency.scitt;

import java.util.Arrays;

/**
 * Parsed COSE protected header for SCITT receipts and status tokens.
 *
 * @param algorithm the signing algorithm (must be -7 for ES256)
 * @param keyId the key identifier (4-byte truncated SHA-256 of SPKI-DER per C2SP)
 * @param vds the Verifiable Data Structure type (1 = RFC9162_SHA256 for Merkle trees)
 * @param cwtClaims CWT claims embedded in the protected header (optional)
 * @param contentType the content type (optional)
 */
public record CoseProtectedHeader(
    int algorithm,
    byte[] keyId,
    Integer vds,
    CwtClaims cwtClaims,
    String contentType
) {
    /**
     * Compact constructor that performs defensive copy of mutable byte array.
     */
    public CoseProtectedHeader {
        keyId = keyId != null ? keyId.clone() : null;
    }

    /**
     * Returns a defensive copy of the key ID.
     *
     * @return a copy of the key ID bytes, or null if not present
     */
    @Override
    public byte[] keyId() {
        return keyId != null ? keyId.clone() : null;
    }

    /**
     * VDS type for RFC 9162 SHA-256 Merkle trees.
     */
    public static final int VDS_RFC9162_SHA256 = 1;

    /**
     * Returns true if this header uses the RFC 9162 Merkle tree VDS.
     *
     * @return true if VDS is RFC9162_SHA256
     */
    public boolean isRfc9162MerkleTree() {
        return vds != null && vds == VDS_RFC9162_SHA256;
    }

    /**
     * Returns the key ID as a hex string for logging/display.
     *
     * @return the key ID in hex, or null if not present
     */
    public String keyIdHex() {
        if (keyId == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : keyId) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CoseProtectedHeader that = (CoseProtectedHeader) o;
        return algorithm == that.algorithm
            && Arrays.equals(keyId, that.keyId)
            && java.util.Objects.equals(vds, that.vds)
            && java.util.Objects.equals(cwtClaims, that.cwtClaims)
            && java.util.Objects.equals(contentType, that.contentType);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(algorithm, vds, cwtClaims, contentType);
        result = 31 * result + Arrays.hashCode(keyId);
        return result;
    }

    @Override
    public String toString() {
        return "CoseProtectedHeader{" +
            "algorithm=" + algorithm +
            ", keyId=" + keyIdHex() +
            ", vds=" + vds +
            ", contentType='" + contentType + '\'' +
            '}';
    }
}
