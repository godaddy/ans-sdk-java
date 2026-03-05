package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Signature on a checkpoint.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CheckpointSignature {

    @JsonProperty("signerName")
    private String signerName;

    @JsonProperty("signatureType")
    private String signatureType;

    @JsonProperty("algorithm")
    private String algorithm;

    @JsonProperty("keyHash")
    private String keyHash;

    @JsonProperty("rawSignature")
    private String rawSignature;

    @JsonProperty("valid")
    private Boolean valid;

    @JsonProperty("kmsKeyId")
    private String kmsKeyId;

    @JsonProperty("timestamp")
    private OffsetDateTime timestamp;

    @JsonProperty("jwsSignature")
    private String jwsSignature;

    @JsonProperty("jwsHeader")
    private Map<String, Object> jwsHeader;

    @JsonProperty("jwsPayload")
    private Map<String, Object> jwsPayload;

    public CheckpointSignature() {
    }

    public String getSignerName() {
        return signerName;
    }

    public void setSignerName(String signerName) {
        this.signerName = signerName;
    }

    public String getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getKeyHash() {
        return keyHash;
    }

    public void setKeyHash(String keyHash) {
        this.keyHash = keyHash;
    }

    public String getRawSignature() {
        return rawSignature;
    }

    public void setRawSignature(String rawSignature) {
        this.rawSignature = rawSignature;
    }

    public Boolean getValid() {
        return valid;
    }

    public void setValid(Boolean valid) {
        this.valid = valid;
    }

    public String getKmsKeyId() {
        return kmsKeyId;
    }

    public void setKmsKeyId(String kmsKeyId) {
        this.kmsKeyId = kmsKeyId;
    }

    public OffsetDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(OffsetDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getJwsSignature() {
        return jwsSignature;
    }

    public void setJwsSignature(String jwsSignature) {
        this.jwsSignature = jwsSignature;
    }

    public Map<String, Object> getJwsHeader() {
        return jwsHeader;
    }

    public void setJwsHeader(Map<String, Object> jwsHeader) {
        this.jwsHeader = jwsHeader;
    }

    public Map<String, Object> getJwsPayload() {
        return jwsPayload;
    }

    public void setJwsPayload(Map<String, Object> jwsPayload) {
        this.jwsPayload = jwsPayload;
    }

    @Override
    public String toString() {
        return "CheckpointSignature{"
            + "signerName='" + signerName + '\''
            + ", algorithm='" + algorithm + '\''
            + ", valid=" + valid
            + '}';
    }
}
