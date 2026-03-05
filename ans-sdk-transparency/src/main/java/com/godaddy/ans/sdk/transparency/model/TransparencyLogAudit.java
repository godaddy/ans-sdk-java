package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Paginated list of transparency log records.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TransparencyLogAudit {

    @JsonProperty("records")
    private List<TransparencyLog> records;

    public TransparencyLogAudit() {
    }

    public List<TransparencyLog> getRecords() {
        return records;
    }

    public void setRecords(List<TransparencyLog> records) {
        this.records = records;
    }

    @Override
    public String toString() {
        return "TransparencyLogAudit{"
            + "records=" + (records != null ? records.size() : 0)
            + '}';
    }
}
