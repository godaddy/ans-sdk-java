package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * V1 schema for ANS Transparency Log entries.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TransparencyLogV1 {

    @JsonProperty("logId")
    private String logId;

    @JsonProperty("producer")
    private ProducerV1 producer;

    public TransparencyLogV1() {
    }

    public String getLogId() {
        return logId;
    }

    public void setLogId(String logId) {
        this.logId = logId;
    }

    public ProducerV1 getProducer() {
        return producer;
    }

    public void setProducer(ProducerV1 producer) {
        this.producer = producer;
    }

    /**
     * Convenience method to get the event from the producer.
     *
     * @return the event, or null if producer is null
     */
    public EventV1 getEvent() {
        return producer != null ? producer.getEvent() : null;
    }

    /**
     * Convenience method to get attestations from the event.
     *
     * @return the attestations, or null if not available
     */
    public AttestationsV1 getAttestations() {
        EventV1 event = getEvent();
        return event != null ? event.getAttestations() : null;
    }

    /**
     * Convenience method to get the ANS name.
     *
     * @return the ANS name, or null if not available
     */
    public String getAnsName() {
        EventV1 event = getEvent();
        return event != null ? event.getAnsName() : null;
    }

    /**
     * Convenience method to get the event type.
     *
     * @return the event type, or null if not available
     */
    public EventTypeV1 getEventType() {
        EventV1 event = getEvent();
        return event != null ? event.getEventType() : null;
    }

    @Override
    public String toString() {
        return "TransparencyLogV1{"
            + "logId='" + logId + '\''
            + ", producer=" + producer
            + '}';
    }
}
