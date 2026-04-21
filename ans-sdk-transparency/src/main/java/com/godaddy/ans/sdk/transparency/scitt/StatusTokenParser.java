package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.transparency.model.CertificateInfo;
import com.godaddy.ans.sdk.transparency.model.CertType;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Parser for SCITT Status Token COSE_Sign1 bytes.
 *
 * <p>Separated from {@link StatusToken} to keep the record focused on being
 * a data carrier with business logic, while parsing logic lives here.</p>
 */
public final class StatusTokenParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(StatusTokenParser.class);

    private StatusTokenParser() {
        // Utility class
    }

    /**
     * Parses a status token from raw COSE_Sign1 bytes.
     *
     * @param coseBytes the raw COSE_Sign1 bytes
     * @return the parsed status token
     * @throws ScittParseException if parsing fails
     */
    public static StatusToken parse(byte[] coseBytes) throws ScittParseException {
        Objects.requireNonNull(coseBytes, "coseBytes cannot be null");

        CoseSign1Parser.ParsedCoseSign1 parsed = CoseSign1Parser.parse(coseBytes);
        return fromParsedCose(parsed);
    }

    /**
     * Creates a StatusToken from an already-parsed COSE_Sign1 structure.
     *
     * @param parsed the parsed COSE_Sign1
     * @return the StatusToken
     * @throws ScittParseException if the payload doesn't contain valid status token data
     */
    public static StatusToken fromParsedCose(CoseSign1Parser.ParsedCoseSign1 parsed) throws ScittParseException {
        Objects.requireNonNull(parsed, "parsed cannot be null");

        CoseProtectedHeader header = parsed.protectedHeader();
        byte[] payload = parsed.payload();

        if (payload == null || payload.length == 0) {
            throw new ScittParseException("Status token payload cannot be empty");
        }

        // Parse the payload as CBOR
        CBORObject payloadCbor;
        try {
            payloadCbor = CBORObject.DecodeFromBytes(payload);
        } catch (Exception e) {
            throw new ScittParseException("Failed to decode status token payload: " + e.getMessage(), e);
        }

        if (payloadCbor.getType() != CBORType.Map) {
            throw new ScittParseException("Status token payload must be a CBOR map");
        }

        // Extract fields from payload using integer keys
        // Key mapping: 1=agent_id, 2=status, 3=iat, 4=exp, 5=ans_name,
        //              6=identity_certs, 7=server_certs, 8=metadata
        String agentId = extractRequiredString(payloadCbor, 1);
        String statusStr = extractRequiredString(payloadCbor, 2);
        StatusToken.Status status = parseStatus(statusStr);

        String ansName = extractOptionalString(payloadCbor, 5);

        // Extract timestamps from CWT claims in header or payload
        Instant issuedAt = null;
        Instant expiresAt = null;

        if (header.cwtClaims() != null) {
            issuedAt = header.cwtClaims().issuedAtTime();
            expiresAt = header.cwtClaims().expirationTime();
        }

        // Payload might override header claims
        Long iatSeconds = extractOptionalLong(payloadCbor, 3);
        Long expSeconds = extractOptionalLong(payloadCbor, 4);

        if (iatSeconds != null) {
            issuedAt = Instant.ofEpochSecond(iatSeconds);
        }
        if (expSeconds != null) {
            expiresAt = Instant.ofEpochSecond(expSeconds);
        }

        // SECURITY: Tokens must have an expiration time - no infinite validity allowed
        if (expiresAt == null) {
            throw new ScittParseException("Status token missing required expiration time (exp claim)");
        }

        // Extract certificate lists
        List<CertificateInfo> identityCerts = extractCertificateList(payloadCbor, 6);
        List<CertificateInfo> serverCerts = extractCertificateList(payloadCbor, 7);

        // Extract metadata hashes
        Map<String, String> metadataHashes = extractMetadataHashes(payloadCbor, 8);

        CoseEnvelope envelope = new CoseEnvelope(
            header,
            parsed.protectedHeaderBytes(),
            payload,
            parsed.signature()
        );

        return new StatusToken(
            agentId,
            status,
            issuedAt,
            expiresAt,
            ansName,
            identityCerts,
            serverCerts,
            metadataHashes,
            envelope
        );
    }

    static StatusToken.Status parseStatus(String statusStr) {
        if (statusStr == null) {
            return StatusToken.Status.UNKNOWN;
        }
        try {
            return StatusToken.Status.valueOf(statusStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Unrecognized status value '{}', treating as UNKNOWN", statusStr);
            return StatusToken.Status.UNKNOWN;
        }
    }

    static String extractRequiredString(CBORObject map, int key) throws ScittParseException {
        return CborExtractors.extractRequiredString(map, key);
    }

    static String extractOptionalString(CBORObject map, int key) {
        return CborExtractors.extractOptionalString(map, key);
    }

    static Long extractOptionalLong(CBORObject map, int key) {
        return CborExtractors.extractOptionalLong(map, key);
    }

    static List<CertificateInfo> extractCertificateList(CBORObject map, int key) {
        CBORObject value = map.get(CBORObject.FromObject(key));
        if (value == null || value.getType() != CBORType.Array) {
            return Collections.emptyList();
        }

        List<CertificateInfo> certs = new ArrayList<>();
        for (int i = 0; i < value.size(); i++) {
            CBORObject certObj = value.get(i);
            if (certObj.getType() == CBORType.Map) {
                // Integer keys: 1=fingerprint, 2=type
                CBORObject fingerprintObj = certObj.get(CBORObject.FromObject(1));
                if (fingerprintObj != null && fingerprintObj.getType() == CBORType.TextString) {
                    CertificateInfo cert = new CertificateInfo();
                    cert.setFingerprint(fingerprintObj.AsString());

                    CBORObject typeObj = certObj.get(CBORObject.FromObject(2));
                    if (typeObj != null && typeObj.getType() == CBORType.TextString) {
                        CertType certType = CertType.fromString(typeObj.AsString());
                        if (certType != null) {
                            cert.setType(certType);
                        }
                    }
                    certs.add(cert);
                }
            } else if (certObj.getType() == CBORType.TextString) {
                // Simple string fingerprint
                CertificateInfo cert = new CertificateInfo();
                cert.setFingerprint(certObj.AsString());
                certs.add(cert);
            }
        }
        return certs;
    }

    static Map<String, String> extractMetadataHashes(CBORObject map, int key) {
        CBORObject value = map.get(CBORObject.FromObject(key));
        if (value == null || value.getType() != CBORType.Map) {
            return Collections.emptyMap();
        }

        Map<String, String> hashes = new HashMap<>();
        for (CBORObject hashKey : value.getKeys()) {
            if (hashKey.getType() == CBORType.TextString) {
                CBORObject hashValue = value.get(hashKey);
                if (hashValue != null && hashValue.getType() == CBORType.TextString) {
                    hashes.put(hashKey.AsString(), hashValue.AsString());
                }
            }
        }
        return hashes;
    }
}
