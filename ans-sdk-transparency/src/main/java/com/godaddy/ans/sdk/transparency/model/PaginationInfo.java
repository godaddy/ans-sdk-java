package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Pagination metadata.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PaginationInfo {

    @JsonProperty("first")
    private String first;

    @JsonProperty("previous")
    private String previous;

    @JsonProperty("next")
    private String next;

    @JsonProperty("last")
    private String last;

    @JsonProperty("total")
    private Long total;

    @JsonProperty("nextOffset")
    private Integer nextOffset;

    public PaginationInfo() {
    }

    public String getFirst() {
        return first;
    }

    public void setFirst(String first) {
        this.first = first;
    }

    public String getPrevious() {
        return previous;
    }

    public void setPrevious(String previous) {
        this.previous = previous;
    }

    public String getNext() {
        return next;
    }

    public void setNext(String next) {
        this.next = next;
    }

    public String getLast() {
        return last;
    }

    public void setLast(String last) {
        this.last = last;
    }

    public Long getTotal() {
        return total;
    }

    public void setTotal(Long total) {
        this.total = total;
    }

    public Integer getNextOffset() {
        return nextOffset;
    }

    public void setNextOffset(Integer nextOffset) {
        this.nextOffset = nextOffset;
    }

    @Override
    public String toString() {
        return "PaginationInfo{"
            + "total=" + total
            + ", nextOffset=" + nextOffset
            + '}';
    }
}
