package com.godaddy.ans.sdk.transparency.scitt;

import java.util.Arrays;
import java.util.Objects;

/**
 * COSE_Sign1 envelope containing the protected header, raw bytes, payload, and signature.
 *
 * <p>Extracted from {@link StatusToken} to reduce parameter count and
 * provide a reusable container for COSE_Sign1 structure components.</p>
 *
 * @param protectedHeader the parsed COSE protected header
 * @param protectedHeaderBytes the raw protected header bytes (for signature verification)
 * @param payload the raw payload bytes
 * @param signature the cryptographic signature
 */
public record CoseEnvelope(
    CoseProtectedHeader protectedHeader,
    byte[] protectedHeaderBytes,
    byte[] payload,
    byte[] signature
) {
    /**
     * Compact constructor performing defensive copies of mutable byte arrays.
     */
    public CoseEnvelope {
        protectedHeaderBytes = protectedHeaderBytes != null
            ? protectedHeaderBytes.clone() : null;
        payload = payload != null ? payload.clone() : null;
        signature = signature != null ? signature.clone() : null;
    }

    @Override
    public byte[] protectedHeaderBytes() {
        return protectedHeaderBytes != null
            ? protectedHeaderBytes.clone() : null;
    }

    @Override
    public byte[] payload() {
        return payload != null ? payload.clone() : null;
    }

    @Override
    public byte[] signature() {
        return signature != null ? signature.clone() : null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CoseEnvelope that = (CoseEnvelope) o;
        return Objects.equals(protectedHeader, that.protectedHeader)
            && Arrays.equals(protectedHeaderBytes, that.protectedHeaderBytes)
            && Arrays.equals(payload, that.payload)
            && Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(protectedHeader);
        result = 31 * result + Arrays.hashCode(protectedHeaderBytes);
        result = 31 * result + Arrays.hashCode(payload);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }
}
