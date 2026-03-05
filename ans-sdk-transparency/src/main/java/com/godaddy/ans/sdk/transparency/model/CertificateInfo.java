package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Certificate information in attestations.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertificateInfo {

    @JsonProperty("fingerprint")
    private String fingerprint;

    @JsonProperty("type")
    private CertType type;

    public CertificateInfo() {
    }

    public CertificateInfo(String fingerprint, CertType type) {
        this.fingerprint = fingerprint;
        this.type = type;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public CertType getType() {
        return type;
    }

    public void setType(CertType type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return "CertificateInfo{"
            + "fingerprint='" + fingerprint + '\''
            + ", type=" + type
            + '}';
    }
}
