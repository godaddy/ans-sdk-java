package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Optional metadata in V0 schema.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class EventMetadataV0 {

    @JsonProperty("agentCardUrl")
    private String agentCardUrl;

    @JsonProperty("ansCapabilities")
    private List<String> ansCapabilities;

    @JsonProperty("description")
    private String description;

    @JsonProperty("endpoint")
    private String endpoint;

    @JsonProperty("raBadgeUrl")
    private String raBadgeUrl;

    public EventMetadataV0() {
    }

    public String getAgentCardUrl() {
        return agentCardUrl;
    }

    public void setAgentCardUrl(String agentCardUrl) {
        this.agentCardUrl = agentCardUrl;
    }

    public List<String> getAnsCapabilities() {
        return ansCapabilities;
    }

    public void setAnsCapabilities(List<String> ansCapabilities) {
        this.ansCapabilities = ansCapabilities;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getRaBadgeUrl() {
        return raBadgeUrl;
    }

    public void setRaBadgeUrl(String raBadgeUrl) {
        this.raBadgeUrl = raBadgeUrl;
    }

    @Override
    public String toString() {
        return "EventMetadataV0{"
            + "endpoint='" + endpoint + '\''
            + ", description='" + description + '\''
            + '}';
    }
}
