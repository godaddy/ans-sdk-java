package com.godaddy.ans.sdk.transparency.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for model classes to ensure getters, setters, and toString work correctly.
 */
class ModelClassesTest {

    @Test
    @DisplayName("RABadge getters and setters should work")
    void raBadgeGettersAndSettersWork() {
        RABadge badge = new RABadge();

        badge.setRaId("test-ra-id");
        badge.setBadgeUrlStatus("active");
        badge.setRenewalStatus("valid");
        badge.setAnsCapabilitiesHash("hash123");

        OffsetDateTime now = OffsetDateTime.now();
        badge.setIssuedAt(now);
        badge.setExpiresAt(now.plusDays(365));

        assertThat(badge.getRaId()).isEqualTo("test-ra-id");
        assertThat(badge.getBadgeUrlStatus()).isEqualTo("active");
        assertThat(badge.getRenewalStatus()).isEqualTo("valid");
        assertThat(badge.getAnsCapabilitiesHash()).isEqualTo("hash123");
        assertThat(badge.getIssuedAt()).isEqualTo(now);
        assertThat(badge.getExpiresAt()).isEqualTo(now.plusDays(365));
    }

    @Test
    @DisplayName("RABadge toString should contain key fields")
    void raBadgeToStringShouldContainKeyFields() {
        RABadge badge = new RABadge();
        badge.setRaId("test-id");
        badge.setBadgeUrlStatus("active");

        String str = badge.toString();

        assertThat(str).contains("test-id");
        assertThat(str).contains("active");
    }

    @Test
    @DisplayName("RABadge attestations should work")
    void raBadgeAttestationsWork() {
        RABadge badge = new RABadge();
        AttestationsV0 attestations = new AttestationsV0();
        badge.setAttestations(attestations);
        badge.setRevocationReasonCode(RevocationReason.KEY_COMPROMISE);

        assertThat(badge.getAttestations()).isSameAs(attestations);
        assertThat(badge.getRevocationReasonCode()).isEqualTo(RevocationReason.KEY_COMPROMISE);
    }

    @Test
    @DisplayName("AttestationsV0 getters and setters should work")
    void attestationsV0GettersAndSettersWork() {
        AttestationsV0 attestations = new AttestationsV0();

        attestations.setServerCertFingerprint("fp123");
        attestations.setClientCertFingerprint("client-fp");
        attestations.setCsrSubmission("csr-data");
        attestations.setDnssecStatus("DNSSEC_VALID");
        attestations.setDomainValidation("VALIDATED");
        attestations.setDomainValidationStatus("COMPLETED");
        attestations.setIdentityCertType("X509-EV-CLIENT");
        attestations.setServerCertType("X509-DV-SERVER");
        attestations.setProtocolExtensionsVerified("true");
        attestations.setDnsRecordsProvisionedStatus("PROVISIONED");

        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_tlsa", "record1");
        attestations.setDnsRecordsProvisioned(dnsRecords);

        assertThat(attestations.getServerCertFingerprint()).isEqualTo("fp123");
        assertThat(attestations.getClientCertFingerprint()).isEqualTo("client-fp");
        assertThat(attestations.getCsrSubmission()).isEqualTo("csr-data");
        assertThat(attestations.getDnssecStatus()).isEqualTo("DNSSEC_VALID");
        assertThat(attestations.getDomainValidation()).isEqualTo("VALIDATED");
        assertThat(attestations.getDomainValidationStatus()).isEqualTo("COMPLETED");
        assertThat(attestations.getIdentityCertType()).isEqualTo("X509-EV-CLIENT");
        assertThat(attestations.getServerCertType()).isEqualTo("X509-DV-SERVER");
        assertThat(attestations.getProtocolExtensionsVerified()).isEqualTo("true");
        assertThat(attestations.getDnsRecordsProvisionedStatus()).isEqualTo("PROVISIONED");
        assertThat(attestations.getDnsRecordsProvisioned()).containsEntry("_tlsa", "record1");
    }

    @Test
    @DisplayName("AttestationsV0 toString should work")
    void attestationsV0ToStringWorks() {
        AttestationsV0 attestations = new AttestationsV0();
        attestations.setServerCertFingerprint("fp123");
        attestations.setClientCertFingerprint("client-fp");

        String str = attestations.toString();
        assertThat(str).contains("fp123");
        assertThat(str).contains("client-fp");
    }

    @Test
    @DisplayName("CertificateInfo getters and setters should work")
    void certificateInfoGettersAndSettersWork() {
        CertificateInfo info = new CertificateInfo();

        info.setFingerprint("SHA256:abc123");
        info.setType(CertType.X509_DV_SERVER);

        assertThat(info.getFingerprint()).isEqualTo("SHA256:abc123");
        assertThat(info.getType()).isEqualTo(CertType.X509_DV_SERVER);
    }

    @Test
    @DisplayName("CertificateInfo constructor should work")
    void certificateInfoConstructorWorks() {
        CertificateInfo info = new CertificateInfo("fp123", CertType.X509_EV_CLIENT);

        assertThat(info.getFingerprint()).isEqualTo("fp123");
        assertThat(info.getType()).isEqualTo(CertType.X509_EV_CLIENT);
    }

    @Test
    @DisplayName("CertificateInfo toString should work")
    void certificateInfoToStringWorks() {
        CertificateInfo info = new CertificateInfo();
        info.setFingerprint("fp123");

        String str = info.toString();
        assertThat(str).contains("fp123");
    }

    @Test
    @DisplayName("EventV0 getters and setters should work")
    void eventV0GettersAndSettersWork() {
        EventV0 event = new EventV0();
        EventMetadataV0 metadata = new EventMetadataV0();
        RABadge badge = new RABadge();
        OffsetDateTime now = OffsetDateTime.now();

        event.setMetadata(metadata);
        event.setEventType(EventTypeV0.AGENT_ACTIVE);
        event.setAgentFqdn("agent.example.com");
        event.setAgentId("agent-123");
        event.setAnsName("ans-name");
        event.setProtocol("MCP");
        event.setRaBadge(badge);
        event.setTimestamp(now);

        assertThat(event.getMetadata()).isSameAs(metadata);
        assertThat(event.getEventType()).isEqualTo(EventTypeV0.AGENT_ACTIVE);
        assertThat(event.getAgentFqdn()).isEqualTo("agent.example.com");
        assertThat(event.getAgentId()).isEqualTo("agent-123");
        assertThat(event.getAnsName()).isEqualTo("ans-name");
        assertThat(event.getProtocol()).isEqualTo("MCP");
        assertThat(event.getRaBadge()).isSameAs(badge);
        assertThat(event.getTimestamp()).isEqualTo(now);
    }

    @Test
    @DisplayName("EventV0 toString should work")
    void eventV0ToStringWorks() {
        EventV0 event = new EventV0();
        event.setAgentFqdn("agent.example.com");
        event.setAgentId("agent-123");

        String str = event.toString();
        assertThat(str).contains("agent.example.com");
        assertThat(str).contains("agent-123");
    }

    @Test
    @DisplayName("MerkleProof getters and setters should work")
    void merkleProofGettersAndSettersWork() {
        MerkleProof proof = new MerkleProof();

        proof.setLeafIndex(100L);
        proof.setTreeSize(1000L);
        proof.setTreeVersion(5L);
        proof.setRootHash("roothash123");
        proof.setLeafHash("leafhash456");
        proof.setRootSignature("sig789");
        proof.setPath(List.of("hash1", "hash2"));

        assertThat(proof.getLeafIndex()).isEqualTo(100L);
        assertThat(proof.getTreeSize()).isEqualTo(1000L);
        assertThat(proof.getTreeVersion()).isEqualTo(5L);
        assertThat(proof.getRootHash()).isEqualTo("roothash123");
        assertThat(proof.getLeafHash()).isEqualTo("leafhash456");
        assertThat(proof.getRootSignature()).isEqualTo("sig789");
        assertThat(proof.getPath()).containsExactly("hash1", "hash2");
    }

    @Test
    @DisplayName("MerkleProof toString should work")
    void merkleProofToStringWorks() {
        MerkleProof proof = new MerkleProof();
        proof.setLeafHash("leafhash");
        proof.setRootHash("roothash");

        String str = proof.toString();
        assertThat(str).contains("leafhash");
        assertThat(str).contains("roothash");
    }

    @Test
    @DisplayName("PaginationInfo getters and setters should work")
    void paginationInfoGettersAndSettersWork() {
        PaginationInfo info = new PaginationInfo();

        info.setFirst("/api?page=1");
        info.setPrevious("/api?page=2");
        info.setNext("/api?page=4");
        info.setLast("/api?page=10");
        info.setTotal(500L);
        info.setNextOffset(100);

        assertThat(info.getFirst()).isEqualTo("/api?page=1");
        assertThat(info.getPrevious()).isEqualTo("/api?page=2");
        assertThat(info.getNext()).isEqualTo("/api?page=4");
        assertThat(info.getLast()).isEqualTo("/api?page=10");
        assertThat(info.getTotal()).isEqualTo(500L);
        assertThat(info.getNextOffset()).isEqualTo(100);
    }

    @Test
    @DisplayName("PaginationInfo toString should work")
    void paginationInfoToStringWorks() {
        PaginationInfo info = new PaginationInfo();
        info.setTotal(500L);

        String str = info.toString();
        assertThat(str).contains("500");
    }

    @Test
    @DisplayName("CheckpointSignature getters and setters should work")
    void checkpointSignatureGettersAndSettersWork() {
        CheckpointSignature sig = new CheckpointSignature();
        OffsetDateTime now = OffsetDateTime.now();

        sig.setSignerName("signer-1");
        sig.setSignatureType("Ed25519");
        sig.setAlgorithm("SHA256");
        sig.setKeyHash("keyhash123");
        sig.setRawSignature("rawsig");
        sig.setValid(true);
        sig.setKmsKeyId("kms-key-1");
        sig.setTimestamp(now);
        sig.setJwsSignature("jws-sig");

        Map<String, Object> header = new HashMap<>();
        header.put("alg", "ES256");
        sig.setJwsHeader(header);

        Map<String, Object> payload = new HashMap<>();
        payload.put("sub", "test");
        sig.setJwsPayload(payload);

        assertThat(sig.getSignerName()).isEqualTo("signer-1");
        assertThat(sig.getSignatureType()).isEqualTo("Ed25519");
        assertThat(sig.getAlgorithm()).isEqualTo("SHA256");
        assertThat(sig.getKeyHash()).isEqualTo("keyhash123");
        assertThat(sig.getRawSignature()).isEqualTo("rawsig");
        assertThat(sig.getValid()).isTrue();
        assertThat(sig.getKmsKeyId()).isEqualTo("kms-key-1");
        assertThat(sig.getTimestamp()).isEqualTo(now);
        assertThat(sig.getJwsSignature()).isEqualTo("jws-sig");
        assertThat(sig.getJwsHeader()).containsEntry("alg", "ES256");
        assertThat(sig.getJwsPayload()).containsEntry("sub", "test");
    }

    @Test
    @DisplayName("CheckpointSignature toString should work")
    void checkpointSignatureToStringWorks() {
        CheckpointSignature sig = new CheckpointSignature();
        sig.setSignerName("signer-1");
        sig.setAlgorithm("SHA256");

        String str = sig.toString();
        assertThat(str).contains("signer-1");
        assertThat(str).contains("SHA256");
    }

    @Test
    @DisplayName("CheckpointResponse getters and setters should work")
    void checkpointResponseGettersAndSettersWork() {
        CheckpointResponse response = new CheckpointResponse();
        CheckpointSignature sig = new CheckpointSignature();

        response.setLogSize(1000L);
        response.setTreeHeight(10);
        response.setRootHash("root123");
        response.setOriginName("origin-name");
        response.setCheckpointFormat("RFC6962");
        response.setCheckpointText("checkpoint-text");
        response.setPublicKeyPem("-----BEGIN PUBLIC KEY-----");
        response.setSignatures(List.of(sig));

        assertThat(response.getLogSize()).isEqualTo(1000L);
        assertThat(response.getTreeHeight()).isEqualTo(10);
        assertThat(response.getRootHash()).isEqualTo("root123");
        assertThat(response.getOriginName()).isEqualTo("origin-name");
        assertThat(response.getCheckpointFormat()).isEqualTo("RFC6962");
        assertThat(response.getCheckpointText()).isEqualTo("checkpoint-text");
        assertThat(response.getPublicKeyPem()).isEqualTo("-----BEGIN PUBLIC KEY-----");
        assertThat(response.getSignatures()).containsExactly(sig);
    }

    @Test
    @DisplayName("CheckpointResponse toString should work")
    void checkpointResponseToStringWorks() {
        CheckpointResponse response = new CheckpointResponse();
        response.setLogSize(1000L);
        response.setRootHash("root123");

        String str = response.toString();
        assertThat(str).contains("1000");
        assertThat(str).contains("root123");
    }

    @Test
    @DisplayName("CheckpointHistoryParams builder should work")
    void checkpointHistoryParamsBuilderWorks() {
        OffsetDateTime since = OffsetDateTime.now();
        CheckpointHistoryParams params = CheckpointHistoryParams.builder()
            .limit(25)
            .offset(50)
            .fromSize(100)
            .toSize(200)
            .since(since)
            .order("desc")
            .build();

        assertThat(params.getLimit()).isEqualTo(25);
        assertThat(params.getOffset()).isEqualTo(50);
        assertThat(params.getFromSize()).isEqualTo(100);
        assertThat(params.getToSize()).isEqualTo(200);
        assertThat(params.getSince()).isEqualTo(since);
        assertThat(params.getOrder()).isEqualTo("desc");
    }

    @Test
    @DisplayName("CheckpointHistoryParams setters should work")
    void checkpointHistoryParamsSettersWork() {
        CheckpointHistoryParams params = new CheckpointHistoryParams();
        OffsetDateTime since = OffsetDateTime.now();

        params.setLimit(10);
        params.setOffset(20);
        params.setFromSize(30);
        params.setToSize(40);
        params.setSince(since);
        params.setOrder("asc");

        assertThat(params.getLimit()).isEqualTo(10);
        assertThat(params.getOffset()).isEqualTo(20);
        assertThat(params.getFromSize()).isEqualTo(30);
        assertThat(params.getToSize()).isEqualTo(40);
        assertThat(params.getSince()).isEqualTo(since);
        assertThat(params.getOrder()).isEqualTo("asc");
    }

    @Test
    @DisplayName("TransparencyLogAudit getters and setters should work")
    void transparencyLogAuditGettersAndSettersWork() {
        TransparencyLogAudit audit = new TransparencyLogAudit();
        TransparencyLog log = new TransparencyLog();

        audit.setRecords(List.of(log));

        assertThat(audit.getRecords()).containsExactly(log);
    }

    @Test
    @DisplayName("TransparencyLogAudit toString should work")
    void transparencyLogAuditToStringWorks() {
        TransparencyLogAudit audit = new TransparencyLogAudit();
        audit.setRecords(List.of(new TransparencyLog(), new TransparencyLog()));

        String str = audit.toString();
        assertThat(str).contains("2");
    }

    @Test
    @DisplayName("TransparencyLogAudit toString with null records")
    void transparencyLogAuditToStringWithNullRecords() {
        TransparencyLogAudit audit = new TransparencyLogAudit();

        String str = audit.toString();
        assertThat(str).contains("0");
    }

    @Test
    @DisplayName("RevocationReason enum values exist")
    void revocationReasonEnumValuesExist() {
        assertThat(RevocationReason.values()).contains(
            RevocationReason.KEY_COMPROMISE,
            RevocationReason.SUPERSEDED,
            RevocationReason.CESSATION_OF_OPERATION,
            RevocationReason.AA_COMPROMISE,
            RevocationReason.AFFILIATION_CHANGED,
            RevocationReason.CA_COMPROMISE,
            RevocationReason.CERTIFICATE_HOLD,
            RevocationReason.EXPIRED_CERT,
            RevocationReason.PRIVILEGE_WITHDRAWN,
            RevocationReason.REMOVE_FROM_CRL,
            RevocationReason.UNSPECIFIED
        );
    }

    @Test
    @DisplayName("RevocationReason getValue should return string value")
    void revocationReasonGetValueWorks() {
        assertThat(RevocationReason.KEY_COMPROMISE.getValue()).isEqualTo("KEY_COMPROMISE");
        assertThat(RevocationReason.SUPERSEDED.getValue()).isEqualTo("SUPERSEDED");
    }

    @Test
    @DisplayName("RevocationReason fromString should parse correctly")
    void revocationReasonFromStringWorks() {
        assertThat(RevocationReason.fromString("KEY_COMPROMISE")).isEqualTo(RevocationReason.KEY_COMPROMISE);
        assertThat(RevocationReason.fromString("key_compromise")).isEqualTo(RevocationReason.KEY_COMPROMISE);
        assertThat(RevocationReason.fromString(null)).isNull();
        assertThat(RevocationReason.fromString("UNKNOWN")).isNull();
    }

    @Test
    @DisplayName("CertType enum values exist")
    void certTypeEnumValuesExist() {
        assertThat(CertType.values()).contains(
            CertType.X509_DV_SERVER,
            CertType.X509_EV_CLIENT,
            CertType.X509_EV_SERVER,
            CertType.X509_OV_CLIENT,
            CertType.X509_OV_SERVER
        );
    }

    @Test
    @DisplayName("CertType getValue should return string value")
    void certTypeGetValueWorks() {
        assertThat(CertType.X509_DV_SERVER.getValue()).isEqualTo("X509-DV-SERVER");
        assertThat(CertType.X509_EV_CLIENT.getValue()).isEqualTo("X509-EV-CLIENT");
    }

    @Test
    @DisplayName("CertType fromString should parse correctly")
    void certTypeFromStringWorks() {
        assertThat(CertType.fromString("X509-DV-SERVER")).isEqualTo(CertType.X509_DV_SERVER);
        assertThat(CertType.fromString("x509-dv-server")).isEqualTo(CertType.X509_DV_SERVER);
        assertThat(CertType.fromString(null)).isNull();
        assertThat(CertType.fromString("UNKNOWN")).isNull();
    }

    @Test
    @DisplayName("EventTypeV0 enum values exist")
    void eventTypeV0EnumValuesExist() {
        assertThat(EventTypeV0.values()).contains(
            EventTypeV0.AGENT_ACTIVE,
            EventTypeV0.AGENT_REVOCATION,
            EventTypeV0.CERTIFICATE_EXPIRING,
            EventTypeV0.CERTIFICATE_RENEWED
        );
    }

    @Test
    @DisplayName("EventTypeV0 getValue should return string value")
    void eventTypeV0GetValueWorks() {
        assertThat(EventTypeV0.AGENT_ACTIVE.getValue()).isEqualTo("AGENT_ACTIVE");
        assertThat(EventTypeV0.AGENT_REVOCATION.getValue()).isEqualTo("AGENT_REVOCATION");
    }

    @Test
    @DisplayName("EventTypeV0 fromString should parse correctly")
    void eventTypeV0FromStringWorks() {
        assertThat(EventTypeV0.fromString("AGENT_ACTIVE")).isEqualTo(EventTypeV0.AGENT_ACTIVE);
        assertThat(EventTypeV0.fromString("agent_active")).isEqualTo(EventTypeV0.AGENT_ACTIVE);
        assertThat(EventTypeV0.fromString(null)).isNull();
        assertThat(EventTypeV0.fromString("UNKNOWN")).isNull();
    }

    @Test
    @DisplayName("SchemaVersion enum values exist")
    void schemaVersionEnumValuesExist() {
        assertThat(SchemaVersion.values()).contains(
            SchemaVersion.V0,
            SchemaVersion.V1
        );
    }

    @Test
    @DisplayName("SchemaVersion getValue should return string value")
    void schemaVersionGetValueWorks() {
        assertThat(SchemaVersion.V0.getValue()).isEqualTo("V0");
        assertThat(SchemaVersion.V1.getValue()).isEqualTo("V1");
    }

    @Test
    @DisplayName("SchemaVersion fromString should parse correctly")
    void schemaVersionFromStringWorks() {
        assertThat(SchemaVersion.fromString("V0")).isEqualTo(SchemaVersion.V0);
        assertThat(SchemaVersion.fromString("v1")).isEqualTo(SchemaVersion.V1);
        assertThat(SchemaVersion.fromString(null)).isEqualTo(SchemaVersion.V0); // defaults to V0
        assertThat(SchemaVersion.fromString("")).isEqualTo(SchemaVersion.V0); // defaults to V0
        assertThat(SchemaVersion.fromString("UNKNOWN")).isEqualTo(SchemaVersion.V0); // defaults to V0
    }

    // ==================== V1 Model Classes ====================

    @Test
    @DisplayName("EventTypeV1 enum values exist")
    void eventTypeV1EnumValuesExist() {
        assertThat(EventTypeV1.values()).contains(
            EventTypeV1.AGENT_REGISTERED,
            EventTypeV1.AGENT_REVOKED,
            EventTypeV1.AGENT_DEPRECATED,
            EventTypeV1.AGENT_RENEWED
        );
    }

    @Test
    @DisplayName("EventTypeV1 getValue should return string value")
    void eventTypeV1GetValueWorks() {
        assertThat(EventTypeV1.AGENT_REGISTERED.getValue()).isEqualTo("AGENT_REGISTERED");
        assertThat(EventTypeV1.AGENT_REVOKED.getValue()).isEqualTo("AGENT_REVOKED");
    }

    @Test
    @DisplayName("EventTypeV1 fromString should parse correctly")
    void eventTypeV1FromStringWorks() {
        assertThat(EventTypeV1.fromString("AGENT_REGISTERED")).isEqualTo(EventTypeV1.AGENT_REGISTERED);
        assertThat(EventTypeV1.fromString("agent_registered")).isEqualTo(EventTypeV1.AGENT_REGISTERED);
        assertThat(EventTypeV1.fromString(null)).isNull();
        assertThat(EventTypeV1.fromString("UNKNOWN")).isNull();
    }

    @Test
    @DisplayName("AgentV1 getters and setters should work")
    void agentV1GettersAndSettersWork() {
        AgentV1 agent = new AgentV1();

        agent.setHost("agent.example.com");
        agent.setVersion("v1.0.0");
        agent.setName("Test Agent");
        agent.setProviderId("provider-123");

        assertThat(agent.getHost()).isEqualTo("agent.example.com");
        assertThat(agent.getVersion()).isEqualTo("v1.0.0");
        assertThat(agent.getName()).isEqualTo("Test Agent");
        assertThat(agent.getProviderId()).isEqualTo("provider-123");
    }

    @Test
    @DisplayName("AgentV1 toString should work")
    void agentV1ToStringWorks() {
        AgentV1 agent = new AgentV1();
        agent.setHost("agent.example.com");
        agent.setVersion("v1.0.0");

        String str = agent.toString();
        assertThat(str).contains("agent.example.com");
        assertThat(str).contains("v1.0.0");
    }

    @Test
    @DisplayName("AttestationsV1 getters and setters should work")
    void attestationsV1GettersAndSettersWork() {
        AttestationsV1 attestations = new AttestationsV1();
        CertificateInfo serverCert = new CertificateInfo("fp1", CertType.X509_DV_SERVER);
        CertificateInfo identityCert = new CertificateInfo("fp2", CertType.X509_EV_CLIENT);

        attestations.setDomainValidation("ACME-DNS-01");
        attestations.setServerCert(serverCert);
        attestations.setIdentityCert(identityCert);

        assertThat(attestations.getDomainValidation()).isEqualTo("ACME-DNS-01");
        assertThat(attestations.getServerCert()).isSameAs(serverCert);
        assertThat(attestations.getIdentityCert()).isSameAs(identityCert);
    }

    @Test
    @DisplayName("AttestationsV1 toString should work")
    void attestationsV1ToStringWorks() {
        AttestationsV1 attestations = new AttestationsV1();
        attestations.setDomainValidation("ACME-DNS-01");

        String str = attestations.toString();
        assertThat(str).contains("ACME-DNS-01");
    }

    @Test
    @DisplayName("EventV1 getters and setters should work")
    void eventV1GettersAndSettersWork() {
        EventV1 event = new EventV1();
        AgentV1 agent = new AgentV1();
        AttestationsV1 attestations = new AttestationsV1();
        OffsetDateTime now = OffsetDateTime.now();

        event.setAnsId("ans-123");
        event.setAnsName("ans://v1.0.0.agent.example");
        event.setEventType(EventTypeV1.AGENT_REGISTERED);
        event.setAgent(agent);
        event.setAttestations(attestations);
        event.setIssuedAt(now);
        event.setExpiresAt(now.plusYears(1));
        event.setRaId("ra.example.com");
        event.setTimestamp(now);
        event.setRevocationReasonCode(RevocationReason.KEY_COMPROMISE);

        assertThat(event.getAnsId()).isEqualTo("ans-123");
        assertThat(event.getAnsName()).isEqualTo("ans://v1.0.0.agent.example");
        assertThat(event.getEventType()).isEqualTo(EventTypeV1.AGENT_REGISTERED);
        assertThat(event.getAgent()).isSameAs(agent);
        assertThat(event.getAttestations()).isSameAs(attestations);
        assertThat(event.getIssuedAt()).isEqualTo(now);
        assertThat(event.getExpiresAt()).isEqualTo(now.plusYears(1));
        assertThat(event.getRaId()).isEqualTo("ra.example.com");
        assertThat(event.getTimestamp()).isEqualTo(now);
        assertThat(event.getRevocationReasonCode()).isEqualTo(RevocationReason.KEY_COMPROMISE);
    }

    @Test
    @DisplayName("EventV1 toString should work")
    void eventV1ToStringWorks() {
        EventV1 event = new EventV1();
        event.setAnsId("ans-123");
        event.setAnsName("ans://v1.0.0.agent.example");

        String str = event.toString();
        assertThat(str).contains("ans-123");
    }

    @Test
    @DisplayName("ProducerV1 getters and setters should work")
    void producerV1GettersAndSettersWork() {
        ProducerV1 producer = new ProducerV1();
        EventV1 event = new EventV1();

        producer.setEvent(event);
        producer.setKeyId("key-123");
        producer.setSignature("sig-456");

        assertThat(producer.getEvent()).isSameAs(event);
        assertThat(producer.getKeyId()).isEqualTo("key-123");
        assertThat(producer.getSignature()).isEqualTo("sig-456");
    }

    @Test
    @DisplayName("ProducerV1 toString should work")
    void producerV1ToStringWorks() {
        ProducerV1 producer = new ProducerV1();
        producer.setKeyId("key-123");
        producer.setSignature("sig-456");

        String str = producer.toString();
        assertThat(str).contains("key-123");
    }

    @Test
    @DisplayName("ProducerV0 getters and setters should work")
    void producerV0GettersAndSettersWork() {
        ProducerV0 producer = new ProducerV0();
        EventV0 event = new EventV0();

        producer.setEvent(event);
        producer.setKeyId("key-123");
        producer.setSignature("sig-456");

        assertThat(producer.getEvent()).isSameAs(event);
        assertThat(producer.getKeyId()).isEqualTo("key-123");
        assertThat(producer.getSignature()).isEqualTo("sig-456");
    }

    @Test
    @DisplayName("ProducerV0 toString should work")
    void producerV0ToStringWorks() {
        ProducerV0 producer = new ProducerV0();
        producer.setKeyId("key-123");

        String str = producer.toString();
        assertThat(str).contains("key-123");
    }

    @Test
    @DisplayName("EventMetadataV0 getters and setters should work")
    void eventMetadataV0GettersAndSettersWork() {
        EventMetadataV0 metadata = new EventMetadataV0();

        metadata.setAgentCardUrl("https://example.com/card");
        metadata.setAnsCapabilities(List.of("cap1", "cap2"));
        metadata.setDescription("Test description");
        metadata.setEndpoint("https://example.com/api");
        metadata.setRaBadgeUrl("https://example.com/badge");

        assertThat(metadata.getAgentCardUrl()).isEqualTo("https://example.com/card");
        assertThat(metadata.getAnsCapabilities()).containsExactly("cap1", "cap2");
        assertThat(metadata.getDescription()).isEqualTo("Test description");
        assertThat(metadata.getEndpoint()).isEqualTo("https://example.com/api");
        assertThat(metadata.getRaBadgeUrl()).isEqualTo("https://example.com/badge");
    }

    @Test
    @DisplayName("EventMetadataV0 toString should work")
    void eventMetadataV0ToStringWorks() {
        EventMetadataV0 metadata = new EventMetadataV0();
        metadata.setEndpoint("https://example.com/api");
        metadata.setDescription("Test description");

        String str = metadata.toString();
        assertThat(str).contains("https://example.com/api");
        assertThat(str).contains("Test description");
    }

    @Test
    @DisplayName("TransparencyLogV0 getters and setters should work")
    void transparencyLogV0GettersAndSettersWork() {
        TransparencyLogV0 log = new TransparencyLogV0();
        ProducerV0 producer = new ProducerV0();

        log.setLogId("log-123");
        log.setProducer(producer);

        assertThat(log.getLogId()).isEqualTo("log-123");
        assertThat(log.getProducer()).isSameAs(producer);
    }

    @Test
    @DisplayName("TransparencyLogV0 toString should work")
    void transparencyLogV0ToStringWorks() {
        TransparencyLogV0 log = new TransparencyLogV0();
        log.setLogId("log-123");

        String str = log.toString();
        assertThat(str).contains("log-123");
    }

    @Test
    @DisplayName("TransparencyLogV0 getAnsName should extract from producer event")
    void transparencyLogV0GetAnsNameWorks() {
        TransparencyLogV0 log = new TransparencyLogV0();
        ProducerV0 producer = new ProducerV0();
        EventV0 event = new EventV0();
        event.setAnsName("ans://v1.0.0.agent.example");
        producer.setEvent(event);
        log.setProducer(producer);

        assertThat(log.getAnsName()).isEqualTo("ans://v1.0.0.agent.example");
    }

    @Test
    @DisplayName("TransparencyLogV0 getAnsName should return null when no producer")
    void transparencyLogV0GetAnsNameNullWhenNoProducer() {
        TransparencyLogV0 log = new TransparencyLogV0();

        assertThat(log.getAnsName()).isNull();
    }

    @Test
    @DisplayName("TransparencyLogV1 getters and setters should work")
    void transparencyLogV1GettersAndSettersWork() {
        TransparencyLogV1 log = new TransparencyLogV1();
        ProducerV1 producer = new ProducerV1();

        log.setLogId("log-v1-123");
        log.setProducer(producer);

        assertThat(log.getLogId()).isEqualTo("log-v1-123");
        assertThat(log.getProducer()).isSameAs(producer);
    }

    @Test
    @DisplayName("TransparencyLogV1 toString should work")
    void transparencyLogV1ToStringWorks() {
        TransparencyLogV1 log = new TransparencyLogV1();
        log.setLogId("log-v1-123");

        String str = log.toString();
        assertThat(str).contains("log-v1-123");
    }

    @Test
    @DisplayName("TransparencyLogV1 getEventType should extract from producer event")
    void transparencyLogV1GetEventTypeWorks() {
        TransparencyLogV1 log = new TransparencyLogV1();
        ProducerV1 producer = new ProducerV1();
        EventV1 event = new EventV1();
        event.setEventType(EventTypeV1.AGENT_REGISTERED);
        producer.setEvent(event);
        log.setProducer(producer);

        assertThat(log.getEventType()).isEqualTo(EventTypeV1.AGENT_REGISTERED);
    }

    @Test
    @DisplayName("TransparencyLogV1 getAnsName should extract from producer event")
    void transparencyLogV1GetAnsNameWorks() {
        TransparencyLogV1 log = new TransparencyLogV1();
        ProducerV1 producer = new ProducerV1();
        EventV1 event = new EventV1();
        event.setAnsName("ans://v1.0.0.agent.example");
        producer.setEvent(event);
        log.setProducer(producer);

        assertThat(log.getAnsName()).isEqualTo("ans://v1.0.0.agent.example");
    }

    @Test
    @DisplayName("TransparencyLogV1 getAttestations should extract from event")
    void transparencyLogV1GetAttestationsWorks() {
        TransparencyLogV1 log = new TransparencyLogV1();
        ProducerV1 producer = new ProducerV1();
        EventV1 event = new EventV1();
        AttestationsV1 attestations = new AttestationsV1();
        event.setAttestations(attestations);
        producer.setEvent(event);
        log.setProducer(producer);

        assertThat(log.getAttestations()).isSameAs(attestations);
    }

    @Test
    @DisplayName("TransparencyLogV1 getEvent should extract from producer")
    void transparencyLogV1GetEventWorks() {
        TransparencyLogV1 log = new TransparencyLogV1();
        ProducerV1 producer = new ProducerV1();
        EventV1 event = new EventV1();
        producer.setEvent(event);
        log.setProducer(producer);

        assertThat(log.getEvent()).isSameAs(event);
    }

    @Test
    @DisplayName("TransparencyLogV1 convenience methods return null when no producer")
    void transparencyLogV1ConvenienceMethodsReturnNullWhenNoProducer() {
        TransparencyLogV1 log = new TransparencyLogV1();

        assertThat(log.getEventType()).isNull();
        assertThat(log.getAnsName()).isNull();
        assertThat(log.getEvent()).isNull();
        assertThat(log.getAttestations()).isNull();
    }

    @Test
    @DisplayName("TransparencyLogV1 getAttestations returns null when event is null")
    void transparencyLogV1GetAttestationsReturnsNullWhenEventIsNull() {
        TransparencyLogV1 log = new TransparencyLogV1();
        ProducerV1 producer = new ProducerV1();
        // producer with no event set
        log.setProducer(producer);

        assertThat(log.getAttestations()).isNull();
    }

    @Test
    @DisplayName("TransparencyLog convenience methods should work for V1")
    void transparencyLogConvenienceMethodsShouldWorkForV1() {
        TransparencyLog log = new TransparencyLog();
        log.setSchemaVersion("V1");

        // Create V1 payload
        TransparencyLogV1 v1 = new TransparencyLogV1();
        ProducerV1 producer = new ProducerV1();
        EventV1 event = new EventV1();
        AgentV1 agent = new AgentV1();
        agent.setHost("agent.example.com");
        AttestationsV1 attestations = new AttestationsV1();
        CertificateInfo serverCert = new CertificateInfo("SHA256:server", CertType.X509_DV_SERVER);
        CertificateInfo identityCert = new CertificateInfo("SHA256:identity", CertType.X509_EV_CLIENT);
        attestations.setServerCert(serverCert);
        attestations.setIdentityCert(identityCert);
        event.setAgent(agent);
        event.setAttestations(attestations);
        event.setAnsName("ans://v1.0.0.agent.example");
        producer.setEvent(event);
        v1.setProducer(producer);
        log.setParsedPayload(v1);

        assertThat(log.isV1()).isTrue();
        assertThat(log.isV0()).isFalse();
        assertThat(log.getServerCertFingerprint()).isEqualTo("SHA256:server");
        assertThat(log.getIdentityCertFingerprint()).isEqualTo("SHA256:identity");
        assertThat(log.getAgentHost()).isEqualTo("agent.example.com");
        assertThat(log.getAnsName()).isEqualTo("ans://v1.0.0.agent.example");
    }

    @Test
    @DisplayName("TransparencyLog convenience methods should work for V0")
    void transparencyLogConvenienceMethodsShouldWorkForV0() {
        TransparencyLog log = new TransparencyLog();
        log.setSchemaVersion("V0");

        // Create V0 payload
        TransparencyLogV0 v0 = new TransparencyLogV0();
        ProducerV0 producer = new ProducerV0();
        EventV0 event = new EventV0();
        event.setAgentFqdn("agent.example.com");
        event.setAnsName("ans://v1.0.0.agent.example");
        RABadge badge = new RABadge();
        AttestationsV0 attestations = new AttestationsV0();
        attestations.setServerCertFingerprint("SHA256:server");
        attestations.setClientCertFingerprint("SHA256:client");
        badge.setAttestations(attestations);
        event.setRaBadge(badge);
        producer.setEvent(event);
        v0.setProducer(producer);
        log.setParsedPayload(v0);

        assertThat(log.isV0()).isTrue();
        assertThat(log.isV1()).isFalse();
        assertThat(log.getServerCertFingerprint()).isEqualTo("SHA256:server");
        assertThat(log.getIdentityCertFingerprint()).isEqualTo("SHA256:client");
        assertThat(log.getAgentHost()).isEqualTo("agent.example.com");
        assertThat(log.getAnsName()).isEqualTo("ans://v1.0.0.agent.example");
    }

    @Test
    @DisplayName("TransparencyLog getV1Payload and getV0Payload should return typed payload")
    void transparencyLogGetTypedPayloadWorks() {
        TransparencyLog logV1 = new TransparencyLog();
        TransparencyLogV1 v1 = new TransparencyLogV1();
        logV1.setParsedPayload(v1);

        assertThat(logV1.getV1Payload()).isSameAs(v1);
        assertThat(logV1.getV0Payload()).isNull();

        TransparencyLog logV0 = new TransparencyLog();
        TransparencyLogV0 v0 = new TransparencyLogV0();
        logV0.setParsedPayload(v0);

        assertThat(logV0.getV0Payload()).isSameAs(v0);
        assertThat(logV0.getV1Payload()).isNull();
    }

    @Test
    @DisplayName("TransparencyLog convenience methods return null when no payload")
    void transparencyLogConvenienceMethodsReturnNullWhenNoPayload() {
        TransparencyLog log = new TransparencyLog();

        assertThat(log.getServerCertFingerprint()).isNull();
        assertThat(log.getIdentityCertFingerprint()).isNull();
        assertThat(log.getAgentHost()).isNull();
        assertThat(log.getAnsName()).isNull();
    }

    @Test
    @DisplayName("CheckpointHistoryResponse getters and setters should work")
    void checkpointHistoryResponseGettersAndSettersWork() {
        CheckpointHistoryResponse response = new CheckpointHistoryResponse();
        CheckpointResponse checkpoint = new CheckpointResponse();
        PaginationInfo pagination = new PaginationInfo();

        response.setCheckpoints(List.of(checkpoint));
        response.setPagination(pagination);

        assertThat(response.getCheckpoints()).containsExactly(checkpoint);
        assertThat(response.getPagination()).isSameAs(pagination);
    }

    @Test
    @DisplayName("CheckpointHistoryResponse toString should work")
    void checkpointHistoryResponseToStringWorks() {
        CheckpointHistoryResponse response = new CheckpointHistoryResponse();
        CheckpointResponse checkpoint = new CheckpointResponse();
        response.setCheckpoints(List.of(checkpoint, checkpoint));

        String str = response.toString();
        assertThat(str).contains("2");
    }

    @Test
    @DisplayName("CheckpointHistoryResponse toString with null checkpoints")
    void checkpointHistoryResponseToStringWithNullCheckpoints() {
        CheckpointHistoryResponse response = new CheckpointHistoryResponse();

        String str = response.toString();
        assertThat(str).contains("0");
    }

    @Test
    @DisplayName("AgentAuditParams getters and setters should work")
    void agentAuditParamsGettersAndSettersWork() {
        AgentAuditParams params = new AgentAuditParams();

        params.setOffset(10);
        params.setLimit(25);

        assertThat(params.getOffset()).isEqualTo(10);
        assertThat(params.getLimit()).isEqualTo(25);
    }

    @Test
    @DisplayName("AgentAuditParams builder should work")
    void agentAuditParamsBuilderWorks() {
        AgentAuditParams params = AgentAuditParams.builder()
            .offset(10)
            .limit(25)
            .build();

        assertThat(params.getOffset()).isEqualTo(10);
        assertThat(params.getLimit()).isEqualTo(25);
    }
}
