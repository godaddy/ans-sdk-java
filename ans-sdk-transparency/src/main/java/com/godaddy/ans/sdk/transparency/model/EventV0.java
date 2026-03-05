package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;

/**
 * Event structure in V0 schema.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class EventV0 {

    @JsonProperty("agentFqdn")
    private String agentFqdn;

    @JsonProperty("agentId")
    private String agentId;

    @JsonProperty("ansName")
    private String ansName;

    @JsonProperty("eventType")
    private EventTypeV0 eventType;

    @JsonProperty("protocol")
    private String protocol;

    @JsonProperty("raBadge")
    private RABadge raBadge;

    @JsonProperty("timestamp")
    private OffsetDateTime timestamp;

    @JsonProperty("metadata")
    private EventMetadataV0 metadata;

    public EventV0() {
    }

    public String getAgentFqdn() {
        return agentFqdn;
    }

    public void setAgentFqdn(String agentFqdn) {
        this.agentFqdn = agentFqdn;
    }

    public String getAgentId() {
        return agentId;
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public String getAnsName() {
        return ansName;
    }

    public void setAnsName(String ansName) {
        this.ansName = ansName;
    }

    public EventTypeV0 getEventType() {
        return eventType;
    }

    public void setEventType(EventTypeV0 eventType) {
        this.eventType = eventType;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public RABadge getRaBadge() {
        return raBadge;
    }

    public void setRaBadge(RABadge raBadge) {
        this.raBadge = raBadge;
    }

    public OffsetDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(OffsetDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public EventMetadataV0 getMetadata() {
        return metadata;
    }

    public void setMetadata(EventMetadataV0 metadata) {
        this.metadata = metadata;
    }

    @Override
    public String toString() {
        return "EventV0{"
            + "agentFqdn='" + agentFqdn + '\''
            + ", agentId='" + agentId + '\''
            + ", ansName='" + ansName + '\''
            + ", eventType=" + eventType
            + ", timestamp=" + timestamp
            + '}';
    }
}
