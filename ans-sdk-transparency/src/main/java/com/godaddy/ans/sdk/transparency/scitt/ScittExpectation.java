package com.godaddy.ans.sdk.transparency.scitt;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Expected verification state from SCITT artifacts (receipt + status token).
 *
 * <p>This class uses factory methods to ensure valid state combinations
 * and prevent construction of invalid expectations.</p>
 */
public final class ScittExpectation {

    /**
     * Verification status from SCITT artifacts.
     */
    public enum Status {
        /** Both receipt and status token verified successfully */
        VERIFIED,
        /** Receipt signature or Merkle proof invalid */
        INVALID_RECEIPT,
        /** Status token signature invalid or malformed */
        INVALID_TOKEN,
        /** Status token has expired */
        TOKEN_EXPIRED,
        /** Agent status is REVOKED */
        AGENT_REVOKED,
        /** Agent status is not ACTIVE (WARNING, DEPRECATED, EXPIRED) */
        AGENT_INACTIVE,
        /** Required public key not found */
        KEY_NOT_FOUND,
        /** SCITT artifacts not present (no headers) */
        NOT_PRESENT,
        /** Parse error in SCITT artifacts */
        PARSE_ERROR
    }

    private final Status status;
    private final List<String> validServerCertFingerprints;
    private final List<String> validIdentityCertFingerprints;
    private final String agentHost;
    private final String ansName;
    private final Map<String, String> metadataHashes;
    private final String failureReason;
    private final StatusToken statusToken;

    private ScittExpectation(
            Status status,
            List<String> validServerCertFingerprints,
            List<String> validIdentityCertFingerprints,
            String agentHost,
            String ansName,
            Map<String, String> metadataHashes,
            String failureReason,
            StatusToken statusToken) {
        this.status = Objects.requireNonNull(status, "status cannot be null");
        this.validServerCertFingerprints = validServerCertFingerprints != null
            ? List.copyOf(validServerCertFingerprints) : List.of();
        this.validIdentityCertFingerprints = validIdentityCertFingerprints != null
            ? List.copyOf(validIdentityCertFingerprints) : List.of();
        this.agentHost = agentHost;
        this.ansName = ansName;
        this.metadataHashes = metadataHashes != null ? Map.copyOf(metadataHashes) : Map.of();
        this.failureReason = failureReason;
        this.statusToken = statusToken;
    }

    // ==================== Factory Methods ====================

    /**
     * Creates a verified expectation with all valid data.
     *
     * @param serverCertFingerprints valid server certificate fingerprints
     * @param identityCertFingerprints valid identity certificate fingerprints
     * @param agentHost the agent's host
     * @param ansName the agent's ANS name
     * @param metadataHashes the metadata hashes
     * @param statusToken the verified status token
     * @return verified expectation
     */
    public static ScittExpectation verified(
            List<String> serverCertFingerprints,
            List<String> identityCertFingerprints,
            String agentHost,
            String ansName,
            Map<String, String> metadataHashes,
            StatusToken statusToken) {
        return new ScittExpectation(
            Status.VERIFIED,
            serverCertFingerprints,
            identityCertFingerprints,
            agentHost,
            ansName,
            metadataHashes,
            null,
            statusToken
        );
    }

    /**
     * Creates an expectation indicating invalid receipt.
     *
     * @param reason the failure reason
     * @return invalid receipt expectation
     */
    public static ScittExpectation invalidReceipt(String reason) {
        return new ScittExpectation(
            Status.INVALID_RECEIPT,
            null, null, null, null, null,
            reason,
            null
        );
    }

    /**
     * Creates an expectation indicating invalid status token.
     *
     * @param reason the failure reason
     * @return invalid token expectation
     */
    public static ScittExpectation invalidToken(String reason) {
        return new ScittExpectation(
            Status.INVALID_TOKEN,
            null, null, null, null, null,
            reason,
            null
        );
    }

    /**
     * Creates an expectation indicating expired status token.
     *
     * @return expired token expectation
     */
    public static ScittExpectation expired() {
        return new ScittExpectation(
            Status.TOKEN_EXPIRED,
            null, null, null, null, null,
            "Status token has expired",
            null
        );
    }

    /**
     * Creates an expectation indicating agent is revoked.
     *
     * @param ansName the revoked agent's ANS name
     * @return revoked agent expectation
     */
    public static ScittExpectation revoked(String ansName) {
        return new ScittExpectation(
            Status.AGENT_REVOKED,
            null, null, null, ansName, null,
            "Agent registration has been revoked",
            null
        );
    }

    /**
     * Creates an expectation indicating agent is not active.
     *
     * @param status the agent's actual status
     * @param ansName the agent's ANS name
     * @return inactive agent expectation
     */
    public static ScittExpectation inactive(StatusToken.Status status, String ansName) {
        return new ScittExpectation(
            Status.AGENT_INACTIVE,
            null, null, null, ansName, null,
            "Agent status is " + status,
            null
        );
    }

    /**
     * Creates an expectation indicating required key not found.
     *
     * @param reason the failure reason
     * @return key not found expectation
     */
    public static ScittExpectation keyNotFound(String reason) {
        return new ScittExpectation(
            Status.KEY_NOT_FOUND,
            null, null, null, null, null,
            reason,
            null
        );
    }

    /**
     * Creates an expectation indicating SCITT artifacts not present.
     *
     * @return not present expectation
     */
    public static ScittExpectation notPresent() {
        return new ScittExpectation(
            Status.NOT_PRESENT,
            null, null, null, null, null,
            "SCITT headers not present in response",
            null
        );
    }

    /**
     * Creates an expectation indicating parse error.
     *
     * @param reason the parse error reason
     * @return parse error expectation
     */
    public static ScittExpectation parseError(String reason) {
        return new ScittExpectation(
            Status.PARSE_ERROR,
            null, null, null, null, null,
            reason,
            null
        );
    }

    // ==================== Accessors ====================

    public Status status() {
        return status;
    }

    public List<String> validServerCertFingerprints() {
        return validServerCertFingerprints;
    }

    public List<String> validIdentityCertFingerprints() {
        return validIdentityCertFingerprints;
    }

    public String agentHost() {
        return agentHost;
    }

    public String ansName() {
        return ansName;
    }

    public Map<String, String> metadataHashes() {
        return metadataHashes;
    }

    public String failureReason() {
        return failureReason;
    }

    public StatusToken statusToken() {
        return statusToken;
    }

    /**
     * Returns true if SCITT verification was successful.
     *
     * @return true if verified
     */
    public boolean isVerified() {
        return status == Status.VERIFIED;
    }

    /**
     * Returns true if SCITT satus NOT_FOUND.
     *
     * @return true if verified
     */
    public boolean isKeyNotFound() {
        return status == Status.KEY_NOT_FOUND;
    }

    /**
     * Returns true if this expectation represents a failure that should block the connection.
     *
     * @return true if this is a blocking failure
     */
    public boolean shouldFail() {
        return switch (status) {
            case VERIFIED -> false;
            case NOT_PRESENT -> false;  // Not a failure, just means fallback to badge
            case INVALID_RECEIPT, INVALID_TOKEN, TOKEN_EXPIRED,
                 AGENT_REVOKED, AGENT_INACTIVE, KEY_NOT_FOUND, PARSE_ERROR -> true;
        };
    }

    /**
     * Returns true if SCITT artifacts were not present (should fall back to badge).
     *
     * @return true if not present
     */
    public boolean isNotPresent() {
        return status == Status.NOT_PRESENT;
    }

    @Override
    public String toString() {
        if (status == Status.VERIFIED) {
            return "ScittExpectation{status=VERIFIED, ansName='" + ansName +
                "', serverCerts=" + validServerCertFingerprints.size() +
                ", identityCerts=" + validIdentityCertFingerprints.size() + "}";
        }
        return "ScittExpectation{status=" + status +
            ", reason='" + failureReason + "'}";
    }
}
