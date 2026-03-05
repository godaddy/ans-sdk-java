package com.godaddy.ans.sdk.transparency.model;

/**
 * Query parameters for agent audit.
 */
public class AgentAuditParams {

    private int offset;
    private int limit;

    public AgentAuditParams() {
    }

    public AgentAuditParams(int offset, int limit) {
        this.offset = offset;
        this.limit = limit;
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }

    /**
     * Creates a builder for AgentAuditParams.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for AgentAuditParams.
     */
    public static class Builder {
        private int offset;
        private int limit;

        public Builder offset(int offset) {
            this.offset = offset;
            return this;
        }

        public Builder limit(int limit) {
            this.limit = limit;
            return this;
        }

        public AgentAuditParams build() {
            return new AgentAuditParams(offset, limit);
        }
    }
}
