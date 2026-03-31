package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.transparency.model.CertificateInfo;

import java.time.Duration;
import java.time.Instant;
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
 * @param agentId            the agent's unique identifier
 * @param status             the agent's current status
 * @param issuedAt           when the token was issued
 * @param expiresAt          when the token expires
 * @param ansName            the agent's ANS name
 * @param validIdentityCerts valid identity certificate fingerprints
 * @param validServerCerts   valid server certificate fingerprints
 * @param metadataHashes     map of protocol to metadata hash (SHA256:...)
 * @param coseEnvelope       the COSE_Sign1 envelope with header, bytes, payload, and signature
 */
public record StatusToken(
    String agentId,
    Status status,
    Instant issuedAt,
    Instant expiresAt,
    String ansName,
    List<CertificateInfo> validIdentityCerts,
    List<CertificateInfo> validServerCerts,
    Map<String, String> metadataHashes,
    CoseEnvelope coseEnvelope
) {

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
     * Returns the parsed COSE protected header.
     *
     * @return the protected header, or null if no envelope is present
     */
    public CoseProtectedHeader protectedHeader() {
        return coseEnvelope != null ? coseEnvelope.protectedHeader() : null;
    }

    /**
     * Returns the raw protected header bytes used for signature verification.
     *
     * @return the protected header bytes, or null if no envelope is present
     */
    public byte[] protectedHeaderBytes() {
        return coseEnvelope != null ? coseEnvelope.protectedHeaderBytes() : null;
    }

    /**
     * Returns the raw payload bytes.
     *
     * @return the payload bytes, or null if no envelope is present
     */
    public byte[] payload() {
        return coseEnvelope != null ? coseEnvelope.payload() : null;
    }

    /**
     * Returns the cryptographic signature.
     *
     * @return the signature bytes, or null if no envelope is present
     */
    public byte[] signature() {
        return coseEnvelope != null ? coseEnvelope.signature() : null;
    }

    /**
     * Parses a status token from raw COSE_Sign1 bytes.
     *
     * @param coseBytes the raw COSE_Sign1 bytes
     * @return the parsed status token
     * @throws ScittParseException if parsing fails
     */
    public static StatusToken parse(byte[] coseBytes) throws ScittParseException {
        return StatusTokenParser.parse(coseBytes);
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
            && Objects.equals(validIdentityCerts, that.validIdentityCerts)
            && Objects.equals(validServerCerts, that.validServerCerts)
            && Objects.equals(metadataHashes, that.metadataHashes)
            && Objects.equals(coseEnvelope, that.coseEnvelope);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(agentId, status, issuedAt, expiresAt, ansName,
            validIdentityCerts, validServerCerts, metadataHashes);
        result = 31 * result + Objects.hashCode(coseEnvelope);
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
