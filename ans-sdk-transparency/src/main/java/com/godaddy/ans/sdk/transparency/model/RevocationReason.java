package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * RFC 5280 revocation reason codes.
 */
public enum RevocationReason {
    AA_COMPROMISE("AA_COMPROMISE"),
    AFFILIATION_CHANGED("AFFILIATION_CHANGED"),
    CA_COMPROMISE("CA_COMPROMISE"),
    CERTIFICATE_HOLD("CERTIFICATE_HOLD"),
    CESSATION_OF_OPERATION("CESSATION_OF_OPERATION"),
    EXPIRED_CERT("EXPIRED_CERT"),
    KEY_COMPROMISE("KEY_COMPROMISE"),
    PRIVILEGE_WITHDRAWN("PRIVILEGE_WITHDRAWN"),
    REMOVE_FROM_CRL("REMOVE_FROM_CRL"),
    SUPERSEDED("SUPERSEDED"),
    UNSPECIFIED("UNSPECIFIED");

    private final String value;

    RevocationReason(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Parses a revocation reason from string.
     *
     * @param value the string value
     * @return the revocation reason, or null if unknown
     */
    public static RevocationReason fromString(String value) {
        if (value == null) {
            return null;
        }
        for (RevocationReason reason : values()) {
            if (reason.value.equalsIgnoreCase(value)) {
                return reason;
            }
        }
        return null;
    }
}
