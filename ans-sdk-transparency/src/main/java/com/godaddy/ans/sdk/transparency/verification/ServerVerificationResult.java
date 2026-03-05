package com.godaddy.ans.sdk.transparency.verification;

import com.godaddy.ans.sdk.transparency.model.TransparencyLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Result of verifying a server against the ANS transparency log.
 *
 * <p>This is used when a client wants to verify that a server it is connecting
 * to is a registered ANS agent with a valid certificate.</p>
 */
public final class ServerVerificationResult {

    private final VerificationStatus status;
    private final TransparencyLog registration;
    private final List<String> expectedServerCertFingerprints;
    private final String expectedAgentHost;
    private final String warningMessage;

    private ServerVerificationResult(Builder builder) {
        this.status = Objects.requireNonNull(builder.status, "status is required");
        this.registration = builder.registration;
        this.expectedServerCertFingerprints = builder.expectedServerCertFingerprints != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.expectedServerCertFingerprints))
            : Collections.emptyList();
        this.expectedAgentHost = builder.expectedAgentHost;
        this.warningMessage = builder.warningMessage;
    }

    /**
     * Returns the verification status.
     *
     * @return the status
     */
    public VerificationStatus getStatus() {
        return status;
    }

    /**
     * Returns the transparency log registration, if found.
     *
     * @return the registration, or null if not found
     */
    public TransparencyLog getRegistration() {
        return registration;
    }

    /**
     * Returns the expected server certificate fingerprint from the registration.
     *
     * <p>Use this to verify the server's TLS certificate matches what's in the
     * transparency log. If multiple registrations exist, returns the first fingerprint.</p>
     *
     * @return the expected fingerprint, or null if not available
     * @see #getExpectedServerCertFingerprints()
     */
    public String getExpectedServerCertFingerprint() {
        return expectedServerCertFingerprints.isEmpty() ? null : expectedServerCertFingerprints.get(0);
    }

    /**
     * Returns all expected server certificate fingerprints from the registrations.
     *
     * <p>During version rotation, multiple badge records may exist with different
     * fingerprints. Use this to verify the server's TLS certificate matches ANY
     * of the registered fingerprints.</p>
     *
     * @return list of expected fingerprints (may be empty, never null)
     */
    public List<String> getExpectedServerCertFingerprints() {
        return expectedServerCertFingerprints;
    }

    /**
     * Returns the expected agent host from the registration.
     *
     * <p>Use this to verify the server's certificate CN matches what's in the
     * transparency log.</p>
     *
     * @return the expected agent host, or null if not available
     */
    public String getExpectedAgentHost() {
        return expectedAgentHost;
    }

    /**
     * Returns a warning message if any issues were detected during verification.
     *
     * @return the warning message, or null if no warnings
     */
    public String getWarningMessage() {
        return warningMessage;
    }

    /**
     * Returns true if the verification was successful.
     *
     * <p>A verification is considered successful if the status is VERIFIED
     * or DEPRECATED_OK.</p>
     *
     * @return true if verification succeeded
     */
    public boolean isSuccess() {
        return status == VerificationStatus.VERIFIED
            || status == VerificationStatus.DEPRECATED_OK;
    }

    /**
     * Returns true if the host is not an ANS agent (no ra-badge record).
     *
     * @return true if not an ANS agent
     */
    public boolean isNotAnsAgent() {
        return status == VerificationStatus.NOT_ANS_AGENT;
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String toString() {
        return "ServerVerificationResult{"
            + "status=" + status
            + ", expectedServerCertFingerprints=" + expectedServerCertFingerprints
            + ", expectedAgentHost='" + expectedAgentHost + '\''
            + ", warningMessage='" + warningMessage + '\''
            + '}';
    }

    /**
     * Builder for ServerVerificationResult.
     */
    public static final class Builder {
        private VerificationStatus status;
        private TransparencyLog registration;
        private List<String> expectedServerCertFingerprints;
        private String expectedAgentHost;
        private String warningMessage;

        private Builder() {
        }

        public Builder status(VerificationStatus status) {
            this.status = status;
            return this;
        }

        public Builder registration(TransparencyLog registration) {
            this.registration = registration;
            return this;
        }

        /**
         * Sets a single expected server certificate fingerprint.
         *
         * @param fingerprint the expected fingerprint
         * @return this builder
         */
        public Builder expectedServerCertFingerprint(String fingerprint) {
            if (fingerprint != null) {
                this.expectedServerCertFingerprints = List.of(fingerprint);
            }
            return this;
        }

        /**
         * Sets multiple expected server certificate fingerprints.
         *
         * <p>Use this during version rotation when multiple badge records exist.</p>
         *
         * @param fingerprints the expected fingerprints
         * @return this builder
         */
        public Builder expectedServerCertFingerprints(List<String> fingerprints) {
            this.expectedServerCertFingerprints = fingerprints;
            return this;
        }

        public Builder expectedAgentHost(String agentHost) {
            this.expectedAgentHost = agentHost;
            return this;
        }

        public Builder warningMessage(String message) {
            this.warningMessage = message;
            return this;
        }

        public ServerVerificationResult build() {
            return new ServerVerificationResult(this);
        }
    }
}