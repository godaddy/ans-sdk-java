package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Agent information in V1 schema.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentV1 {

    @JsonProperty("host")
    private String host;

    @JsonProperty("name")
    private String name;

    @JsonProperty("version")
    private String version;

    @JsonProperty("providerId")
    private String providerId;

    public AgentV1() {
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getProviderId() {
        return providerId;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }

    @Override
    public String toString() {
        return "AgentV1{"
            + "host='" + host + '\''
            + ", name='" + name + '\''
            + ", version='" + version + '\''
            + ", providerId='" + providerId + '\''
            + '}';
    }
}
