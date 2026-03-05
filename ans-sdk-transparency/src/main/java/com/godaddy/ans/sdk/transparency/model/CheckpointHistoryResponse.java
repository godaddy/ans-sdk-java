package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Paginated list of checkpoints.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CheckpointHistoryResponse {

    @JsonProperty("checkpoints")
    private List<CheckpointResponse> checkpoints;

    @JsonProperty("pagination")
    private PaginationInfo pagination;

    public CheckpointHistoryResponse() {
    }

    public List<CheckpointResponse> getCheckpoints() {
        return checkpoints;
    }

    public void setCheckpoints(List<CheckpointResponse> checkpoints) {
        this.checkpoints = checkpoints;
    }

    public PaginationInfo getPagination() {
        return pagination;
    }

    public void setPagination(PaginationInfo pagination) {
        this.pagination = pagination;
    }

    @Override
    public String toString() {
        return "CheckpointHistoryResponse{"
            + "checkpoints=" + (checkpoints != null ? checkpoints.size() : 0)
            + ", pagination=" + pagination
            + '}';
    }
}
