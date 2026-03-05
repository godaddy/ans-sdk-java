package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Event types for V1 schema transparency log entries.
 */
public enum EventTypeV1 {
    AGENT_DEPRECATED("AGENT_DEPRECATED"),
    AGENT_REGISTERED("AGENT_REGISTERED"),
    AGENT_RENEWED("AGENT_RENEWED"),
    AGENT_REVOKED("AGENT_REVOKED");

    private final String value;

    EventTypeV1(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Parses an event type from string.
     *
     * @param value the string value
     * @return the event type, or null if unknown
     */
    public static EventTypeV1 fromString(String value) {
        if (value == null) {
            return null;
        }
        for (EventTypeV1 eventType : values()) {
            if (eventType.value.equalsIgnoreCase(value)) {
                return eventType;
            }
        }
        return null;
    }
}