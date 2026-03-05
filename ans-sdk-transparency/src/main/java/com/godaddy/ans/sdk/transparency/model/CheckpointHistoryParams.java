package com.godaddy.ans.sdk.transparency.model;

import java.time.OffsetDateTime;

/**
 * Query parameters for checkpoint history.
 */
public class CheckpointHistoryParams {

    private int limit;
    private int offset;
    private long fromSize;
    private long toSize;
    private OffsetDateTime since;
    private String order;

    public CheckpointHistoryParams() {
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public long getFromSize() {
        return fromSize;
    }

    public void setFromSize(long fromSize) {
        this.fromSize = fromSize;
    }

    public long getToSize() {
        return toSize;
    }

    public void setToSize(long toSize) {
        this.toSize = toSize;
    }

    public OffsetDateTime getSince() {
        return since;
    }

    public void setSince(OffsetDateTime since) {
        this.since = since;
    }

    public String getOrder() {
        return order;
    }

    public void setOrder(String order) {
        this.order = order;
    }

    /**
     * Creates a builder for CheckpointHistoryParams.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for CheckpointHistoryParams.
     */
    public static class Builder {
        private int limit;
        private int offset;
        private long fromSize;
        private long toSize;
        private OffsetDateTime since;
        private String order;

        public Builder limit(int limit) {
            this.limit = limit;
            return this;
        }

        public Builder offset(int offset) {
            this.offset = offset;
            return this;
        }

        public Builder fromSize(long fromSize) {
            this.fromSize = fromSize;
            return this;
        }

        public Builder toSize(long toSize) {
            this.toSize = toSize;
            return this;
        }

        public Builder since(OffsetDateTime since) {
            this.since = since;
            return this;
        }

        public Builder order(String order) {
            this.order = order;
            return this;
        }

        public CheckpointHistoryParams build() {
            CheckpointHistoryParams params = new CheckpointHistoryParams();
            params.limit = this.limit;
            params.offset = this.offset;
            params.fromSize = this.fromSize;
            params.toSize = this.toSize;
            params.since = this.since;
            params.order = this.order;
            return params;
        }
    }
}
