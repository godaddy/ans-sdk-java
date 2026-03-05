package com.godaddy.ans.sdk.transparency.model;

/**
 * Schema version for transparency log entries.
 */
public enum SchemaVersion {
    V0("V0"),
    V1("V1");

    private final String value;

    SchemaVersion(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    /**
     * Parses a schema version from string.
     *
     * @param value the string value
     * @return the schema version, defaults to V0 if null or unknown
     */
    public static SchemaVersion fromString(String value) {
        if (value == null || value.isEmpty()) {
            return V0; // V0 is default for missing version
        }
        for (SchemaVersion version : values()) {
            if (version.value.equalsIgnoreCase(value)) {
                return version;
            }
        }
        return V0; // Default to V0 for unknown versions
    }
}