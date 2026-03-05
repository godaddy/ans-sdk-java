package com.godaddy.ans.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Attestations in V1 schema.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AttestationsV1 {

    @JsonProperty("dnsRecordsProvisioned")
    private Map<String, String> dnsRecordsProvisioned;

    @JsonProperty("domainValidation")
    private String domainValidation;

    @JsonProperty("identityCert")
    private CertificateInfo identityCert;

    @JsonProperty("serverCert")
    private CertificateInfo serverCert;

    public AttestationsV1() {
    }

    public Map<String, String> getDnsRecordsProvisioned() {
        return dnsRecordsProvisioned;
    }

    public void setDnsRecordsProvisioned(Map<String, String> dnsRecordsProvisioned) {
        this.dnsRecordsProvisioned = dnsRecordsProvisioned;
    }

    public String getDomainValidation() {
        return domainValidation;
    }

    public void setDomainValidation(String domainValidation) {
        this.domainValidation = domainValidation;
    }

    public CertificateInfo getIdentityCert() {
        return identityCert;
    }

    public void setIdentityCert(CertificateInfo identityCert) {
        this.identityCert = identityCert;
    }

    public CertificateInfo getServerCert() {
        return serverCert;
    }

    public void setServerCert(CertificateInfo serverCert) {
        this.serverCert = serverCert;
    }

    @Override
    public String toString() {
        return "AttestationsV1{"
            + "dnsRecordsProvisioned=" + dnsRecordsProvisioned
            + ", domainValidation='" + domainValidation + '\''
            + ", identityCert=" + identityCert
            + ", serverCert=" + serverCert
            + '}';
    }
}
