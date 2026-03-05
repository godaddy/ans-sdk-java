package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Event types for V0 schema transparency log entries.
 */
public enum EventTypeV0 {
    AGENT_ACTIVE("AGENT_ACTIVE"),
    AGENT_REVOCATION("AGENT_REVOCATION"),
    CERTIFICATE_EXPIRING("CERTIFICATE_EXPIRING"),
    CERTIFICATE_RENEWED("CERTIFICATE_RENEWED");

    private final String value;

    EventTypeV0(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Parses an event type from string, handling both upper and lower case variants.
     *
     * @param value the string value
     * @return the event type, or null if unknown
     */
    public static EventTypeV0 fromString(String value) {
        if (value == null) {
            return null;
        }
        for (EventTypeV0 eventType : values()) {
            if (eventType.value.equalsIgnoreCase(value)) {
                return eventType;
            }
        }
        return null;
    }
}
