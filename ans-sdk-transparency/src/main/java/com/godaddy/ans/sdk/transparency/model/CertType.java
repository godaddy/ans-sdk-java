package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Certificate types used in attestations.
 */
public enum CertType {
    X509_DV_SERVER("X509-DV-SERVER"),
    X509_EV_CLIENT("X509-EV-CLIENT"),
    X509_EV_SERVER("X509-EV-SERVER"),
    X509_OV_CLIENT("X509-OV-CLIENT"),
    X509_OV_SERVER("X509-OV-SERVER");

    private final String value;

    CertType(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Parses a certificate type from string.
     *
     * @param value the string value
     * @return the certificate type, or null if unknown
     */
    public static CertType fromString(String value) {
        if (value == null) {
            return null;
        }
        for (CertType certType : values()) {
            if (certType.value.equalsIgnoreCase(value)) {
                return certType;
            }
        }
        return null;
    }
}
