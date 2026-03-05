package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Attestations in V0 schema.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AttestationsV0 {

    @JsonProperty("clientCertFingerprint")
    private String clientCertFingerprint;

    @JsonProperty("csrSubmission")
    private String csrSubmission;

    @JsonProperty("dnsRecordsProvisioned")
    private Map<String, String> dnsRecordsProvisioned;

    @JsonProperty("dnsRecordsProvisionedStatus")
    private String dnsRecordsProvisionedStatus;

    @JsonProperty("dnssecStatus")
    private String dnssecStatus;

    @JsonProperty("domainValidation")
    private String domainValidation;

    @JsonProperty("domainValidationStatus")
    private String domainValidationStatus;

    @JsonProperty("identityCertType")
    private String identityCertType;

    @JsonProperty("protocolExtensionsVerified")
    private String protocolExtensionsVerified;

    @JsonProperty("serverCertFingerprint")
    private String serverCertFingerprint;

    @JsonProperty("serverCertType")
    private String serverCertType;

    public AttestationsV0() {
    }

    public String getClientCertFingerprint() {
        return clientCertFingerprint;
    }

    public void setClientCertFingerprint(String clientCertFingerprint) {
        this.clientCertFingerprint = clientCertFingerprint;
    }

    public String getCsrSubmission() {
        return csrSubmission;
    }

    public void setCsrSubmission(String csrSubmission) {
        this.csrSubmission = csrSubmission;
    }

    public Map<String, String> getDnsRecordsProvisioned() {
        return dnsRecordsProvisioned;
    }

    public void setDnsRecordsProvisioned(Map<String, String> dnsRecordsProvisioned) {
        this.dnsRecordsProvisioned = dnsRecordsProvisioned;
    }

    public String getDnsRecordsProvisionedStatus() {
        return dnsRecordsProvisionedStatus;
    }

    public void setDnsRecordsProvisionedStatus(String dnsRecordsProvisionedStatus) {
        this.dnsRecordsProvisionedStatus = dnsRecordsProvisionedStatus;
    }

    public String getDnssecStatus() {
        return dnssecStatus;
    }

    public void setDnssecStatus(String dnssecStatus) {
        this.dnssecStatus = dnssecStatus;
    }

    public String getDomainValidation() {
        return domainValidation;
    }

    public void setDomainValidation(String domainValidation) {
        this.domainValidation = domainValidation;
    }

    public String getDomainValidationStatus() {
        return domainValidationStatus;
    }

    public void setDomainValidationStatus(String domainValidationStatus) {
        this.domainValidationStatus = domainValidationStatus;
    }

    public String getIdentityCertType() {
        return identityCertType;
    }

    public void setIdentityCertType(String identityCertType) {
        this.identityCertType = identityCertType;
    }

    public String getProtocolExtensionsVerified() {
        return protocolExtensionsVerified;
    }

    public void setProtocolExtensionsVerified(String protocolExtensionsVerified) {
        this.protocolExtensionsVerified = protocolExtensionsVerified;
    }

    public String getServerCertFingerprint() {
        return serverCertFingerprint;
    }

    public void setServerCertFingerprint(String serverCertFingerprint) {
        this.serverCertFingerprint = serverCertFingerprint;
    }

    public String getServerCertType() {
        return serverCertType;
    }

    public void setServerCertType(String serverCertType) {
        this.serverCertType = serverCertType;
    }

    @Override
    public String toString() {
        return "AttestationsV0{"
            + "clientCertFingerprint='" + clientCertFingerprint + '\''
            + ", serverCertFingerprint='" + serverCertFingerprint + '\''
            + ", domainValidation='" + domainValidation + '\''
            + '}';
    }
}
