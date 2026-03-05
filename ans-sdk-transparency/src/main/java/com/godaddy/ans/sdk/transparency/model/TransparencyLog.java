package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Transparency log entry for an agent.
 *
 * <p>This is the main response from the transparency log API.
 * Use {@link #getV0Payload()} or {@link #getV1Payload()} to access
 * the strongly-typed payload based on schema version.</p>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TransparencyLog {

    @JsonProperty("merkleProof")
    private MerkleProof merkleProof;

    @JsonProperty("payload")
    private Map<String, Object> payload;

    @JsonProperty("schemaVersion")
    private String schemaVersion;

    @JsonProperty("signature")
    private String signature;

    @JsonProperty("status")
    private String status;

    /**
     * The strongly-typed payload based on schema version.
     * This is populated by the TransparencyService after parsing.
     */
    @JsonIgnore
    private Object parsedPayload;

    public TransparencyLog() {
    }

    public MerkleProof getMerkleProof() {
        return merkleProof;
    }

    public void setMerkleProof(MerkleProof merkleProof) {
        this.merkleProof = merkleProof;
    }

    public Map<String, Object> getPayload() {
        return payload;
    }

    public void setPayload(Map<String, Object> payload) {
        this.payload = payload;
    }

    public String getSchemaVersion() {
        return schemaVersion;
    }

    public void setSchemaVersion(String schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Object getParsedPayload() {
        return parsedPayload;
    }

    public void setParsedPayload(Object parsedPayload) {
        this.parsedPayload = parsedPayload;
    }

    /**
     * Returns the parsed payload as a V1 schema object, or null if not V1.
     *
     * @return the V1 payload, or null
     */
    public TransparencyLogV1 getV1Payload() {
        if (parsedPayload instanceof TransparencyLogV1) {
            return (TransparencyLogV1) parsedPayload;
        }
        return null;
    }

    /**
     * Returns the parsed payload as a V0 schema object, or null if not V0.
     *
     * @return the V0 payload, or null
     */
    public TransparencyLogV0 getV0Payload() {
        if (parsedPayload instanceof TransparencyLogV0) {
            return (TransparencyLogV0) parsedPayload;
        }
        return null;
    }

    /**
     * Returns true if this is a V1 schema entry.
     *
     * @return true if V1 schema
     */
    public boolean isV1() {
        return "V1".equalsIgnoreCase(schemaVersion) || getV1Payload() != null;
    }

    /**
     * Returns true if this is a V0 schema entry.
     *
     * @return true if V0 schema
     */
    public boolean isV0() {
        return "V0".equalsIgnoreCase(schemaVersion)
            || schemaVersion == null
            || schemaVersion.isEmpty()
            || getV0Payload() != null;
    }

    /**
     * Convenience method to get the server certificate fingerprint.
     *
     * @return the server certificate fingerprint, or null if not available
     */
    public String getServerCertFingerprint() {
        if (isV1()) {
            TransparencyLogV1 v1 = getV1Payload();
            if (v1 != null && v1.getAttestations() != null
                    && v1.getAttestations().getServerCert() != null) {
                return v1.getAttestations().getServerCert().getFingerprint();
            }
        } else if (isV0()) {
            TransparencyLogV0 v0 = getV0Payload();
            if (v0 != null && v0.getAttestations() != null) {
                return v0.getAttestations().getServerCertFingerprint();
            }
        }
        return null;
    }

    /**
     * Convenience method to get the identity certificate fingerprint.
     *
     * @return the identity certificate fingerprint, or null if not available
     */
    public String getIdentityCertFingerprint() {
        if (isV1()) {
            TransparencyLogV1 v1 = getV1Payload();
            if (v1 != null && v1.getAttestations() != null
                    && v1.getAttestations().getIdentityCert() != null) {
                return v1.getAttestations().getIdentityCert().getFingerprint();
            }
        } else if (isV0()) {
            TransparencyLogV0 v0 = getV0Payload();
            if (v0 != null && v0.getAttestations() != null) {
                return v0.getAttestations().getClientCertFingerprint();
            }
        }
        return null;
    }

    /**
     * Convenience method to get the ANS name.
     *
     * @return the ANS name, or null if not available
     */
    public String getAnsName() {
        if (isV1()) {
            TransparencyLogV1 v1 = getV1Payload();
            return v1 != null ? v1.getAnsName() : null;
        } else if (isV0()) {
            TransparencyLogV0 v0 = getV0Payload();
            return v0 != null ? v0.getAnsName() : null;
        }
        return null;
    }

    /**
     * Convenience method to get the agent host (FQDN).
     *
     * <p>This is the {@code agent.host} field from V1 schema or
     * {@code agentFqdn} from V0 schema.</p>
     *
     * @return the agent host, or null if not available
     */
    public String getAgentHost() {
        if (isV1()) {
            TransparencyLogV1 v1 = getV1Payload();
            if (v1 != null && v1.getEvent() != null && v1.getEvent().getAgent() != null) {
                return v1.getEvent().getAgent().getHost();
            }
        } else if (isV0()) {
            TransparencyLogV0 v0 = getV0Payload();
            if (v0 != null && v0.getEvent() != null) {
                return v0.getEvent().getAgentFqdn();
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return "TransparencyLog{"
            + "status='" + status + '\''
            + ", schemaVersion='" + schemaVersion + '\''
            + ", merkleProof=" + merkleProof
            + '}';
    }
}