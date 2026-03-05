package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;

/**
 * RA badge in V0 schema.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RABadge {

    @JsonProperty("ansCapabilitiesHash")
    private String ansCapabilitiesHash;

    @JsonProperty("attestations")
    private AttestationsV0 attestations;

    @JsonProperty("badgeUrlStatus")
    private String badgeUrlStatus;

    @JsonProperty("expiresAt")
    private OffsetDateTime expiresAt;

    @JsonProperty("issuedAt")
    private OffsetDateTime issuedAt;

    @JsonProperty("raId")
    private String raId;

    @JsonProperty("renewalStatus")
    private String renewalStatus;

    @JsonProperty("revocationReasonCode")
    private RevocationReason revocationReasonCode;

    public RABadge() {
    }

    public String getAnsCapabilitiesHash() {
        return ansCapabilitiesHash;
    }

    public void setAnsCapabilitiesHash(String ansCapabilitiesHash) {
        this.ansCapabilitiesHash = ansCapabilitiesHash;
    }

    public AttestationsV0 getAttestations() {
        return attestations;
    }

    public void setAttestations(AttestationsV0 attestations) {
        this.attestations = attestations;
    }

    public String getBadgeUrlStatus() {
        return badgeUrlStatus;
    }

    public void setBadgeUrlStatus(String badgeUrlStatus) {
        this.badgeUrlStatus = badgeUrlStatus;
    }

    public OffsetDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(OffsetDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public OffsetDateTime getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(OffsetDateTime issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getRaId() {
        return raId;
    }

    public void setRaId(String raId) {
        this.raId = raId;
    }

    public String getRenewalStatus() {
        return renewalStatus;
    }

    public void setRenewalStatus(String renewalStatus) {
        this.renewalStatus = renewalStatus;
    }

    public RevocationReason getRevocationReasonCode() {
        return revocationReasonCode;
    }

    public void setRevocationReasonCode(RevocationReason revocationReasonCode) {
        this.revocationReasonCode = revocationReasonCode;
    }

    @Override
    public String toString() {
        return "RABadge{"
            + "badgeUrlStatus='" + badgeUrlStatus + '\''
            + ", issuedAt=" + issuedAt
            + ", expiresAt=" + expiresAt
            + ", raId='" + raId + '\''
            + '}';
    }
}
