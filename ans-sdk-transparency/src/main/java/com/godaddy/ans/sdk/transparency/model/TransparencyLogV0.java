package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * V0 schema for ANS Transparency Log entries.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TransparencyLogV0 {

    @JsonProperty("logId")
    private String logId;

    @JsonProperty("producer")
    private ProducerV0 producer;

    public TransparencyLogV0() {
    }

    public String getLogId() {
        return logId;
    }

    public void setLogId(String logId) {
        this.logId = logId;
    }

    public ProducerV0 getProducer() {
        return producer;
    }

    public void setProducer(ProducerV0 producer) {
        this.producer = producer;
    }

    /**
     * Convenience method to get the event from the producer.
     *
     * @return the event, or null if producer is null
     */
    public EventV0 getEvent() {
        return producer != null ? producer.getEvent() : null;
    }

    /**
     * Convenience method to get the RA badge from the event.
     *
     * @return the RA badge, or null if not available
     */
    public RABadge getRaBadge() {
        EventV0 event = getEvent();
        return event != null ? event.getRaBadge() : null;
    }

    /**
     * Convenience method to get attestations from the RA badge.
     *
     * @return the attestations, or null if not available
     */
    public AttestationsV0 getAttestations() {
        RABadge badge = getRaBadge();
        return badge != null ? badge.getAttestations() : null;
    }

    /**
     * Convenience method to get the ANS name.
     *
     * @return the ANS name, or null if not available
     */
    public String getAnsName() {
        EventV0 event = getEvent();
        return event != null ? event.getAnsName() : null;
    }

    /**
     * Convenience method to get the event type.
     *
     * @return the event type, or null if not available
     */
    public EventTypeV0 getEventType() {
        EventV0 event = getEvent();
        return event != null ? event.getEventType() : null;
    }

    @Override
    public String toString() {
        return "TransparencyLogV0{"
            + "logId='" + logId + '\''
            + ", producer=" + producer
            + '}';
    }
}
