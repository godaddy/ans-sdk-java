package com.godaddy.ans.sdk.transparency.scitt;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.util.Objects;

/**
 * Parser for COSE_Sign1 structures (CBOR tag 18) as defined in RFC 9052.
 *
 * <p>COSE_Sign1 is a CBOR structure containing:</p>
 * <ul>
 *   <li>Protected header (CBOR byte string containing encoded CBOR map)</li>
 *   <li>Unprotected header (CBOR map, typically empty)</li>
 *   <li>Payload (CBOR byte string or null for detached)</li>
 *   <li>Signature (CBOR byte string)</li>
 * </ul>
 *
 * <p><b>Security:</b> This parser enforces ES256 (algorithm -7) as the only
 * accepted signing algorithm to prevent algorithm substitution attacks.</p>
 */
public final class CoseSign1Parser {

    /**
     * CBOR tag for COSE_Sign1 structures.
     */
    public static final int COSE_SIGN1_TAG = 18;

    /**
     * ES256 algorithm identifier (ECDSA with SHA-256 on P-256 curve).
     */
    public static final int ES256_ALGORITHM = -7;

    /**
     * Expected signature length for ES256 in IEEE P1363 format (r || s, each 32 bytes).
     */
    public static final int ES256_SIGNATURE_LENGTH = 64;

    /**
     * MAX_COSE_SIZE - 1MB.
     */
    private static final int MAX_COSE_SIZE = 1024 * 1024;

    private CoseSign1Parser() {
        // Utility class
    }

    /**
     * Parses a COSE_Sign1 structure from raw CBOR bytes.
     *
     * @param coseBytes the raw COSE_Sign1 bytes
     * @return the parsed COSE_Sign1 structure
     * @throws ScittParseException if parsing fails or security validation fails
     */
    public static ParsedCoseSign1 parse(byte[] coseBytes) throws ScittParseException {
        Objects.requireNonNull(coseBytes, "coseBytes cannot be null");
        if (coseBytes.length > MAX_COSE_SIZE) {
            throw new ScittParseException("COSE payload exceeds maximum size");
        }
        try {
            CBORObject cborObject = CBORObject.DecodeFromBytes(coseBytes);
            return parseFromCbor(cborObject);
        } catch (ScittParseException e) {
            throw e;
        } catch (Exception e) {
            throw new ScittParseException("Failed to decode CBOR: " + e.getMessage(), e);
        }
    }

    /**
     * Parses a COSE_Sign1 structure from a decoded CBOR object.
     *
     * @param cborObject the decoded CBOR object
     * @return the parsed COSE_Sign1 structure
     * @throws ScittParseException if parsing fails or security validation fails
     */
    public static ParsedCoseSign1 parseFromCbor(CBORObject cborObject) throws ScittParseException {
        Objects.requireNonNull(cborObject, "cborObject cannot be null");

        // Verify COSE_Sign1 tag
        if (!cborObject.HasMostOuterTag(COSE_SIGN1_TAG)) {
            throw new ScittParseException("Expected COSE_Sign1 tag (18), got: " +
                (cborObject.getMostOuterTag() != null ? cborObject.getMostOuterTag() : "no tag"));
        }

        CBORObject untagged = cborObject.UntagOne();

        // COSE_Sign1 is an array of 4 elements
        if (untagged.getType() != CBORType.Array || untagged.size() != 4) {
            throw new ScittParseException("COSE_Sign1 must be an array of 4 elements, got: " +
                untagged.getType() + " with " + (untagged.getType() == CBORType.Array ? untagged.size() : 0)
                    + " elements");
        }

        // Extract components
        byte[] protectedHeaderBytes = extractByteString(untagged, 0, "protected header");
        CBORObject unprotectedHeader = untagged.get(1);  // Keep as CBORObject, avoid encode/decode round-trip
        byte[] payload = extractOptionalByteString(untagged, 2, "payload");
        byte[] signature = extractByteString(untagged, 3, "signature");

        // Parse protected header
        CoseProtectedHeader protectedHeader = parseProtectedHeader(protectedHeaderBytes);

        // Validate signature length for ES256
        if (signature.length != ES256_SIGNATURE_LENGTH) {
            throw new ScittParseException(
                "Invalid ES256 signature length: expected " + ES256_SIGNATURE_LENGTH +
                " bytes (IEEE P1363 format), got " + signature.length);
        }

        return new ParsedCoseSign1(
            protectedHeaderBytes,
            protectedHeader,
            unprotectedHeader,
            payload,
            signature
        );
    }

    /**
     * Parses the protected header CBOR map.
     *
     * @param protectedHeaderBytes the encoded protected header
     * @return the parsed protected header
     * @throws ScittParseException if parsing fails or algorithm is not ES256
     */
    private static CoseProtectedHeader parseProtectedHeader(byte[] protectedHeaderBytes) throws ScittParseException {
        if (protectedHeaderBytes == null || protectedHeaderBytes.length == 0) {
            throw new ScittParseException("Protected header cannot be empty");
        }

        CBORObject headerMap;
        try {
            headerMap = CBORObject.DecodeFromBytes(protectedHeaderBytes);
        } catch (Exception e) {
            throw new ScittParseException("Failed to decode protected header: " + e.getMessage(), e);
        }

        if (headerMap.getType() != CBORType.Map) {
            throw new ScittParseException("Protected header must be a CBOR map");
        }

        // Extract algorithm (label 1) - REQUIRED
        CBORObject algObject = headerMap.get(CBORObject.FromObject(1));
        if (algObject == null) {
            throw new ScittParseException("Protected header missing algorithm (label 1)");
        }

        int algorithm = algObject.AsInt32();

        // SECURITY: Reject non-ES256 algorithms to prevent algorithm substitution attacks
        if (algorithm != ES256_ALGORITHM) {
            throw new ScittParseException(
                "Algorithm substitution attack prevented: only ES256 (alg=-7) is accepted, got alg=" + algorithm);
        }

        // Extract key ID (label 4) - Optional but expected for SCITT
        byte[] keyId = null;
        CBORObject kidObject = headerMap.get(CBORObject.FromObject(4));
        if (kidObject != null && kidObject.getType() == CBORType.ByteString) {
            keyId = kidObject.GetByteString();
        }

        // Extract VDS (Verifiable Data Structure) - label 395 per draft-ietf-cose-merkle-tree-proofs
        Integer vds = null;
        CBORObject vdsObject = headerMap.get(CBORObject.FromObject(395));
        if (vdsObject != null) {
            vds = vdsObject.AsInt32();
        }

        // Extract CWT claims if present (label 13 for cwt_claims)
        CwtClaims cwtClaims = null;
        CBORObject cwtObject = headerMap.get(CBORObject.FromObject(13));
        if (cwtObject != null && cwtObject.getType() == CBORType.Map) {
            cwtClaims = parseCwtClaims(cwtObject);
        }

        // Extract content type (label 3) if present
        String contentType = null;
        CBORObject ctObject = headerMap.get(CBORObject.FromObject(3));
        if (ctObject != null) {
            if (ctObject.getType() == CBORType.TextString) {
                contentType = ctObject.AsString();
            } else if (ctObject.getType() == CBORType.Integer) {
                contentType = String.valueOf(ctObject.AsInt32());
            }
        }

        return new CoseProtectedHeader(algorithm, keyId, vds, cwtClaims, contentType);
    }

    /**
     * Parses CWT (CBOR Web Token) claims from a CBOR map.
     */
    private static CwtClaims parseCwtClaims(CBORObject cwtMap) {
        // CWT claim labels per RFC 8392
        Long iat = extractOptionalLong(cwtMap, 6);  // iat (issued at)
        Long exp = extractOptionalLong(cwtMap, 4);  // exp (expiration)
        Long nbf = extractOptionalLong(cwtMap, 5);  // nbf (not before)
        String iss = extractOptionalString(cwtMap, 1);  // iss (issuer)
        String sub = extractOptionalString(cwtMap, 2);  // sub (subject)
        String aud = extractOptionalString(cwtMap, 3);  // aud (audience)

        return new CwtClaims(iss, sub, aud, exp, nbf, iat);
    }

    private static byte[] extractByteString(CBORObject array, int index, String name) throws ScittParseException {
        CBORObject element = array.get(index);
        if (element == null || element.getType() != CBORType.ByteString) {
            throw new ScittParseException(name + " must be a byte string");
        }
        return element.GetByteString();
    }

    private static byte[] extractOptionalByteString(CBORObject array, int index, String name)
            throws ScittParseException {
        CBORObject element = array.get(index);
        if (element == null || element.isNull()) {
            return null;  // Detached payload
        }
        if (element.getType() != CBORType.ByteString) {
            throw new ScittParseException(name + " must be a byte string or null");
        }
        return element.GetByteString();
    }

    private static Long extractOptionalLong(CBORObject map, int label) {
        CBORObject value = map.get(CBORObject.FromObject(label));
        if (value != null && value.isNumber()) {
            return value.AsInt64();
        }
        return null;
    }

    private static String extractOptionalString(CBORObject map, int label) {
        CBORObject value = map.get(CBORObject.FromObject(label));
        if (value != null && value.getType() == CBORType.TextString) {
            return value.AsString();
        }
        return null;
    }

    /**
     * Constructs the Sig_structure for COSE_Sign1 signature verification.
     *
     * <p>Per RFC 9052, the Sig_structure is:</p>
     * <pre>
     * Sig_structure = [
     *   context : "Signature1",
     *   body_protected : empty_or_serialized_map,
     *   external_aad : bstr,
     *   payload : bstr
     * ]
     * </pre>
     *
     * @param protectedHeaderBytes the serialized protected header
     * @param externalAad external additional authenticated data (typically empty)
     * @param payload the payload bytes
     * @return the encoded Sig_structure
     */
    public static byte[] buildSigStructure(byte[] protectedHeaderBytes, byte[] externalAad, byte[] payload) {
        CBORObject sigStructure = CBORObject.NewArray();
        sigStructure.Add("Signature1");
        sigStructure.Add(protectedHeaderBytes != null ? protectedHeaderBytes : new byte[0]);
        sigStructure.Add(externalAad != null ? externalAad : new byte[0]);
        sigStructure.Add(payload != null ? payload : new byte[0]);
        return sigStructure.EncodeToBytes();
    }

    /**
     * Parsed COSE_Sign1 structure.
     *
     * @param protectedHeaderBytes raw bytes of the protected header (needed for signature verification)
     * @param protectedHeader parsed protected header
     * @param unprotectedHeader the unprotected header as a CBORObject (avoids encode/decode round-trip)
     * @param payload the payload bytes (null if detached)
     * @param signature the signature bytes (64 bytes for ES256 in IEEE P1363 format)
     */
    public record ParsedCoseSign1(
        byte[] protectedHeaderBytes,
        CoseProtectedHeader protectedHeader,
        CBORObject unprotectedHeader,
        byte[] payload,
        byte[] signature
    ) {}
}
