package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Cryptographic proof of inclusion in the Merkle tree.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class MerkleProof {

    @JsonProperty("leafHash")
    private String leafHash;

    @JsonProperty("rootHash")
    private String rootHash;

    @JsonProperty("rootSignature")
    private String rootSignature;

    @JsonProperty("treeSize")
    private Long treeSize;

    @JsonProperty("treeVersion")
    private Long treeVersion;

    @JsonProperty("leafIndex")
    private Long leafIndex;

    @JsonProperty("path")
    private List<String> path;

    public MerkleProof() {
    }

    public String getLeafHash() {
        return leafHash;
    }

    public void setLeafHash(String leafHash) {
        this.leafHash = leafHash;
    }

    public String getRootHash() {
        return rootHash;
    }

    public void setRootHash(String rootHash) {
        this.rootHash = rootHash;
    }

    public String getRootSignature() {
        return rootSignature;
    }

    public void setRootSignature(String rootSignature) {
        this.rootSignature = rootSignature;
    }

    public Long getTreeSize() {
        return treeSize;
    }

    public void setTreeSize(Long treeSize) {
        this.treeSize = treeSize;
    }

    public Long getTreeVersion() {
        return treeVersion;
    }

    public void setTreeVersion(Long treeVersion) {
        this.treeVersion = treeVersion;
    }

    public Long getLeafIndex() {
        return leafIndex;
    }

    public void setLeafIndex(Long leafIndex) {
        this.leafIndex = leafIndex;
    }

    public List<String> getPath() {
        return path;
    }

    public void setPath(List<String> path) {
        this.path = path;
    }

    @Override
    public String toString() {
        return "MerkleProof{"
            + "leafHash='" + leafHash + '\''
            + ", rootHash='" + rootHash + '\''
            + ", treeSize=" + treeSize
            + ", leafIndex=" + leafIndex
            + '}';
    }
}
