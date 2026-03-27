package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.transparency.model.CertificateInfo;
import com.godaddy.ans.sdk.transparency.model.CertType;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * SCITT Status Token - a time-bounded assertion about an agent's status.
 *
 * <p>Status tokens are COSE_Sign1 structures signed by the RA (Registration Authority)
 * that assert the current status of an agent. They include:</p>
 * <ul>
 *   <li>Agent ID and ANS name</li>
 *   <li>Current status (ACTIVE, WARNING, DEPRECATED, EXPIRED, REVOKED)</li>
 *   <li>Validity window (issued at, expires at)</li>
 *   <li>Valid certificate fingerprints (identity and server)</li>
 *   <li>Metadata hashes for endpoint protocols</li>
 * </ul>
 *
 * @param agentId the agent's unique identifier
 * @param status the agent's current status
 * @param issuedAt when the token was issued
 * @param expiresAt when the token expires
 * @param ansName the agent's ANS name
 * @param agentHost the agent's host (FQDN)
 * @param validIdentityCerts valid identity certificate fingerprints
 * @param validServerCerts valid server certificate fingerprints
 * @param metadataHashes map of protocol to metadata hash (SHA256:...)
 * @param protectedHeader the COSE protected header
 * @param signature the RA signature
 */
public record StatusToken(
    String agentId,
    Status status,
    Instant issuedAt,
    Instant expiresAt,
    String ansName,
    String agentHost,
    List<CertificateInfo> validIdentityCerts,
    List<CertificateInfo> validServerCerts,
    Map<String, String> metadataHashes,
    CoseProtectedHeader protectedHeader,
    byte[] protectedHeaderBytes,
    byte[] payload,
    byte[] signature
) {

    private static final Logger LOGGER = LoggerFactory.getLogger(StatusToken.class);

    /**
     * Default clock skew tolerance for expiry checks.
     */
    public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

    /**
     * Agent status values.
     */
    public enum Status {
        /** Agent is active and in good standing */
        ACTIVE,
        /** Agent is active but has warnings (e.g., certificate expiring soon) */
        WARNING,
        /** Agent is deprecated and should not be used for new connections */
        DEPRECATED,
        /** Agent registration has expired */
        EXPIRED,
        /** Agent registration has been revoked */
        REVOKED,
        /** Unknown status */
        UNKNOWN
    }

    /**
     * Compact constructor for defensive copying.
     */
    public StatusToken {
        validIdentityCerts = validIdentityCerts != null ? List.copyOf(validIdentityCerts) : List.of();
        validServerCerts = validServerCerts != null ? List.copyOf(validServerCerts) : List.of();
        metadataHashes = metadataHashes != null ? Map.copyOf(metadataHashes) : Map.of();
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
        // Key mapping: 1=agent_id, 2=status, 3=iat, 4=exp, 5=ans_name, 6=identity_certs, 7=server_certs, 8=metadata
        String agentId = extractRequiredString(payloadCbor, 1);
        String statusStr = extractRequiredString(payloadCbor, 2);
        Status status = parseStatus(statusStr);

        String ansName = extractOptionalString(payloadCbor, 5);
        String agentHost = null;  // Not used in TL format

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

        return new StatusToken(
            agentId,
            status,
            issuedAt,
            expiresAt,
            ansName,
            agentHost,
            identityCerts,
            serverCerts,
            metadataHashes,
            header,
            parsed.protectedHeaderBytes(),
            payload,
            parsed.signature()
        );
    }

    /**
     * Checks if this token is expired.
     *
     * @return true if the token is expired
     */
    public boolean isExpired() {
        return isExpired(Instant.now(), DEFAULT_CLOCK_SKEW);
    }

    /**
     * Checks if this token is expired with the specified clock skew tolerance.
     *
     * @param clockSkew the clock skew tolerance
     * @return true if the token is expired
     */
    public boolean isExpired(Duration clockSkew) {
        return isExpired(Instant.now(), clockSkew);
    }

    /**
     * Checks if this token is expired at the given time with clock skew tolerance.
     *
     * <p>SECURITY: Tokens without an expiration time are considered expired.
     * This is a defensive check - parsing should reject such tokens.</p>
     *
     * @param now the current time
     * @param clockSkew the clock skew tolerance
     * @return true if the token is expired or has no expiration time
     */
    public boolean isExpired(Instant now, Duration clockSkew) {
        if (expiresAt == null) {
            return true;  // No expiration set - treat as expired (defensive)
        }
        return now.minus(clockSkew).isAfter(expiresAt);
    }

    /**
     * Returns the server certificate fingerprints as a list of strings.
     *
     * @return list of fingerprints
     */
    public List<String> serverCertFingerprints() {
        return validServerCerts.stream()
            .map(CertificateInfo::getFingerprint)
            .filter(Objects::nonNull)
            .toList();
    }

    /**
     * Returns the identity certificate fingerprints as a list of strings.
     *
     * @return list of fingerprints
     */
    public List<String> identityCertFingerprints() {
        return validIdentityCerts.stream()
            .map(CertificateInfo::getFingerprint)
            .filter(Objects::nonNull)
            .toList();
    }

    /**
     * Computes the recommended refresh interval based on token lifetime.
     *
     * <p>Returns half of (exp - iat) to refresh before expiry.</p>
     *
     * @return the recommended refresh interval, or 5 minutes if cannot be computed
     */
    public Duration computeRefreshInterval() {
        if (issuedAt == null || expiresAt == null) {
            return Duration.ofMinutes(5);  // Default
        }
        Duration lifetime = Duration.between(issuedAt, expiresAt);
        Duration halfLife = lifetime.dividedBy(2);
        // Minimum 1 minute, maximum 1 hour
        if (halfLife.compareTo(Duration.ofMinutes(1)) < 0) {
            return Duration.ofMinutes(1);
        }
        if (halfLife.compareTo(Duration.ofHours(1)) > 0) {
            return Duration.ofHours(1);
        }
        return halfLife;
    }

    private static Status parseStatus(String statusStr) {
        if (statusStr == null) {
            return Status.UNKNOWN;
        }
        try {
            return Status.valueOf(statusStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Unrecognized status value '{}', treating as UNKNOWN", statusStr);
            return Status.UNKNOWN;
        }
    }

    private static String extractRequiredString(CBORObject map, int key) throws ScittParseException {
        CBORObject value = map.get(CBORObject.FromObject(key));
        if (value == null || value.isNull()) {
            throw new ScittParseException("Missing required field at key " + key);
        }
        if (value.getType() != CBORType.TextString) {
            throw new ScittParseException("Field at key " + key + " must be a string");
        }
        return value.AsString();
    }

    private static String extractOptionalString(CBORObject map, int key) {
        CBORObject value = map.get(CBORObject.FromObject(key));
        if (value != null && value.getType() == CBORType.TextString) {
            return value.AsString();
        }
        return null;
    }

    private static Long extractOptionalLong(CBORObject map, int key) {
        CBORObject value = map.get(CBORObject.FromObject(key));
        if (value != null && value.isNumber()) {
            return value.AsInt64();
        }
        return null;
    }

    private static List<CertificateInfo> extractCertificateList(CBORObject map, int key) {
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

    private static Map<String, String> extractMetadataHashes(CBORObject map, int key) {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        StatusToken that = (StatusToken) o;
        return Objects.equals(agentId, that.agentId)
            && status == that.status
            && Objects.equals(issuedAt, that.issuedAt)
            && Objects.equals(expiresAt, that.expiresAt)
            && Objects.equals(ansName, that.ansName)
            && Objects.equals(agentHost, that.agentHost)
            && Objects.equals(validIdentityCerts, that.validIdentityCerts)
            && Objects.equals(validServerCerts, that.validServerCerts)
            && Objects.equals(metadataHashes, that.metadataHashes)
            && Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(agentId, status, issuedAt, expiresAt, ansName, agentHost,
            validIdentityCerts, validServerCerts, metadataHashes);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public String toString() {
        return "StatusToken{" +
            "agentId='" + agentId + '\'' +
            ", status=" + status +
            ", ansName='" + ansName + '\'' +
            ", expiresAt=" + expiresAt +
            ", serverCerts=" + validServerCerts.size() +
            ", identityCerts=" + validIdentityCerts.size() +
            '}';
    }
}
