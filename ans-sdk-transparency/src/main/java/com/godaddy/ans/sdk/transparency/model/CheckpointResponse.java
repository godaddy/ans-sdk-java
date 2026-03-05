package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Current checkpoint information for the transparency log.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CheckpointResponse {

    @JsonProperty("logSize")
    private Long logSize;

    @JsonProperty("treeHeight")
    private Integer treeHeight;

    @JsonProperty("rootHash")
    private String rootHash;

    @JsonProperty("originName")
    private String originName;

    @JsonProperty("checkpointFormat")
    private String checkpointFormat;

    @JsonProperty("checkpointText")
    private String checkpointText;

    @JsonProperty("publicKeyPem")
    private String publicKeyPem;

    @JsonProperty("signatures")
    private List<CheckpointSignature> signatures;

    public CheckpointResponse() {
    }

    public Long getLogSize() {
        return logSize;
    }

    public void setLogSize(Long logSize) {
        this.logSize = logSize;
    }

    public Integer getTreeHeight() {
        return treeHeight;
    }

    public void setTreeHeight(Integer treeHeight) {
        this.treeHeight = treeHeight;
    }

    public String getRootHash() {
        return rootHash;
    }

    public void setRootHash(String rootHash) {
        this.rootHash = rootHash;
    }

    public String getOriginName() {
        return originName;
    }

    public void setOriginName(String originName) {
        this.originName = originName;
    }

    public String getCheckpointFormat() {
        return checkpointFormat;
    }

    public void setCheckpointFormat(String checkpointFormat) {
        this.checkpointFormat = checkpointFormat;
    }

    public String getCheckpointText() {
        return checkpointText;
    }

    public void setCheckpointText(String checkpointText) {
        this.checkpointText = checkpointText;
    }

    public String getPublicKeyPem() {
        return publicKeyPem;
    }

    public void setPublicKeyPem(String publicKeyPem) {
        this.publicKeyPem = publicKeyPem;
    }

    public List<CheckpointSignature> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<CheckpointSignature> signatures) {
        this.signatures = signatures;
    }

    @Override
    public String toString() {
        return "CheckpointResponse{"
            + "logSize=" + logSize
            + ", treeHeight=" + treeHeight
            + ", rootHash='" + rootHash + '\''
            + ", originName='" + originName + '\''
            + '}';
    }
}
