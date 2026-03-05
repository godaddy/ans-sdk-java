package com.godaddy.ans.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Additional tests for DANE/TLSA verification functionality.
 *
 * <p>These tests complement the existing tests in DaneVerifierTest by providing
 * additional coverage for DNS lookup scenarios and the DefaultDaneTlsaVerifier
 * implementation.</p>
 *
 * <p>Note: These tests use a testable subclass approach to avoid real DNS lookups,
 * making them fast and reliable across all environments.</p>
 */
class DaneTlsaVerifierIntegrationTest {

    private static final String TEST_HOSTNAME = "agent.dane.test.example";

    // ==================== DNS Lookup Path Tests ====================

    @Test
    @DisplayName("Should handle DNS lookup returning single TLSA record")
    void shouldHandleDnsLookupReturningSingleTlsaRecord() throws Exception {
        // Given - verifier that returns a single TLSA record
        byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
        SingleRecordVerifier verifier = new SingleRecordVerifier(
            createConfig(), 3, 1, 1, certData);

        // When
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations(TEST_HOSTNAME, 443);

        // Then
        assertThat(expectations).hasSize(1);
        assertThat(expectations.get(0).selector()).isEqualTo(1);
        assertThat(expectations.get(0).matchingType()).isEqualTo(1);
        assertThat(expectations.get(0).expectedData()).isEqualTo(certData);
    }

    @Test
    @DisplayName("Should handle DNS lookup returning multiple TLSA records for rotation")
    void shouldHandleDnsLookupReturningMultipleTlsaRecords() throws Exception {
        // Given - verifier that returns multiple TLSA records (simulating cert rotation)
        byte[] certData1 = hexToBytes("1111111111111111111111111111111111111111111111111111111111111111");
        byte[] certData2 = hexToBytes("2222222222222222222222222222222222222222222222222222222222222222");

        MultiRecordVerifier verifier = new MultiRecordVerifier(createConfig(), List.of(
            new RecordInfo(3, 1, 1, certData1),
            new RecordInfo(3, 1, 1, certData2)
        ));

        // When
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations("rotation." + TEST_HOSTNAME, 443);

        // Then
        assertThat(expectations).hasSize(2);
    }

    @Test
    @DisplayName("Should handle DNS lookup with different TLSA selectors")
    void shouldHandleDnsLookupWithDifferentSelectors() throws Exception {
        // Given - verifier with both full cert (0) and SPKI (1) selectors
        byte[] fullCertData = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        byte[] spkiData = hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        MultiRecordVerifier verifier = new MultiRecordVerifier(createConfig(), List.of(
            new RecordInfo(3, 0, 1, fullCertData),  // Full cert selector
            new RecordInfo(3, 1, 1, spkiData)       // SPKI selector
        ));

        // When
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations("multitlsa." + TEST_HOSTNAME, 443);

        // Then
        assertThat(expectations).hasSize(2);
        boolean hasFullCert = expectations.stream().anyMatch(e -> e.selector() == 0);
        boolean hasSpki = expectations.stream().anyMatch(e -> e.selector() == 1);
        assertThat(hasFullCert).isTrue();
        assertThat(hasSpki).isTrue();
    }

    @Test
    @DisplayName("Should handle DNS lookup with SHA-512 matching type")
    void shouldHandleDnsLookupWithSha512MatchingType() throws Exception {
        // Given - verifier with SHA-512 (matching type 2)
        byte[] sha512Data = hexToBytes(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" +
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        SingleRecordVerifier verifier = new SingleRecordVerifier(
            createConfig(), 3, 1, 2, sha512Data);

        // When
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations(TEST_HOSTNAME, 8443);

        // Then
        assertThat(expectations).hasSize(1);
        assertThat(expectations.get(0).matchingType()).isEqualTo(2); // SHA-512
        assertThat(expectations.get(0).expectedData()).hasSize(64); // 512 bits
    }

    @Test
    @DisplayName("Should return empty when no TLSA record exists")
    void shouldReturnEmptyWhenNoTlsaRecord() throws Exception {
        // Given - verifier that returns no records
        EmptyResultVerifier verifier = new EmptyResultVerifier(createConfig());

        // When
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations("notlsa.example.com", 443);

        // Then
        assertThat(expectations).isEmpty();
    }

    // ==================== Cache Behavior Tests ====================

    @Test
    @DisplayName("Should use cache for subsequent lookups")
    void shouldUseCacheForSubsequentLookups() throws Exception {
        // Given - counting verifier with caching enabled
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.VALIDATE_IF_PRESENT)
            .cacheTtl(Duration.ofMinutes(5))
            .build();

        CountingVerifier verifier = new CountingVerifier(config);

        // When - query same host twice
        verifier.getTlsaExpectations(TEST_HOSTNAME, 443);
        verifier.getTlsaExpectations(TEST_HOSTNAME, 443);

        // Then - second query should use cache
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1);
        assertThat(verifier.cacheSize()).isEqualTo(1);
    }

    @Test
    @DisplayName("Should not use cache when TTL is zero")
    void shouldNotUseCacheWhenTtlIsZero() throws Exception {
        // Given - counting verifier with caching disabled
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.VALIDATE_IF_PRESENT)
            .cacheTtl(Duration.ZERO)
            .build();

        CountingVerifier verifier = new CountingVerifier(config);

        // When - query same host twice
        verifier.getTlsaExpectations(TEST_HOSTNAME, 443);
        verifier.getTlsaExpectations(TEST_HOSTNAME, 443);

        // Then - both queries should trigger DNS lookup
        assertThat(verifier.getDnsLookupCount()).isEqualTo(2);
        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("Should create separate cache entries for different hosts")
    void shouldCreateSeparateCacheEntriesForDifferentHosts() throws Exception {
        // Given - counting verifier with caching
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.VALIDATE_IF_PRESENT)
            .cacheTtl(Duration.ofMinutes(5))
            .build();

        CountingVerifier verifier = new CountingVerifier(config);

        // When - query different hosts
        verifier.getTlsaExpectations("host1.example.com", 443);
        verifier.getTlsaExpectations("host2.example.com", 443);
        verifier.getTlsaExpectations("host1.example.com", 443); // Should use cache

        // Then
        assertThat(verifier.getDnsLookupCount()).isEqualTo(2);
        assertThat(verifier.cacheSize()).isEqualTo(2);
    }

    @Test
    @DisplayName("Should create separate cache entries for different ports")
    void shouldCreateSeparateCacheEntriesForDifferentPorts() throws Exception {
        // Given - counting verifier with caching
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.VALIDATE_IF_PRESENT)
            .cacheTtl(Duration.ofMinutes(5))
            .build();

        CountingVerifier verifier = new CountingVerifier(config);

        // When - query same host with different ports
        verifier.getTlsaExpectations(TEST_HOSTNAME, 443);
        verifier.getTlsaExpectations(TEST_HOSTNAME, 8443);

        // Then - should be separate cache entries
        assertThat(verifier.cacheSize()).isEqualTo(2);
    }

    @Test
    @DisplayName("Should invalidate cache for specific host")
    void shouldInvalidateCacheForSpecificHost() throws Exception {
        // Given - verifier with cached entry
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.VALIDATE_IF_PRESENT)
            .cacheTtl(Duration.ofMinutes(5))
            .build();

        CountingVerifier verifier = new CountingVerifier(config);

        // Populate cache
        verifier.getTlsaExpectations("host1.example.com", 443);
        verifier.getTlsaExpectations("host2.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(2);

        // When - invalidate one entry
        verifier.invalidate("host1.example.com", 443);

        // Then - only one entry remains
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Next lookup for host1 should trigger DNS
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should clear all cache entries")
    void shouldClearAllCacheEntries() throws Exception {
        // Given - verifier with multiple cached entries
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.VALIDATE_IF_PRESENT)
            .cacheTtl(Duration.ofMinutes(5))
            .build();

        CountingVerifier verifier = new CountingVerifier(config);

        verifier.getTlsaExpectations("host1.example.com", 443);
        verifier.getTlsaExpectations("host2.example.com", 443);
        verifier.getTlsaExpectations("host3.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(3);

        // When - clear cache
        verifier.clearCache();

        // Then - cache should be empty
        assertThat(verifier.cacheSize()).isZero();
    }

    // ==================== Policy Tests ====================

    @Test
    @DisplayName("Should skip DNS lookup when policy is DISABLED")
    void shouldSkipDnsLookupWhenPolicyIsDisabled() throws Exception {
        // Given - verifier with DISABLED policy
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .build();

        CountingVerifier verifier = new CountingVerifier(config);

        // When
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations(TEST_HOSTNAME, 443);

        // Then - no DNS lookup should occur
        assertThat(expectations).isEmpty();
        assertThat(verifier.getDnsLookupCount()).isZero();
    }

    @Test
    @DisplayName("hasTlsaRecord should return false when policy is DISABLED")
    void hasTlsaRecordShouldReturnFalseWhenDisabled() throws Exception {
        // Given - verifier with DISABLED policy
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .build();

        CountingVerifier verifier = new CountingVerifier(config);

        // When/Then
        assertThat(verifier.hasTlsaRecord(TEST_HOSTNAME, 443)).isFalse();
        assertThat(verifier.getDnsLookupCount()).isZero();
    }

    @Test
    @DisplayName("hasTlsaRecord should return true when record exists")
    void hasTlsaRecordShouldReturnTrueWhenExists() throws Exception {
        // Given
        byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
        SingleRecordVerifier verifier = new SingleRecordVerifier(
            createConfig(), 3, 1, 1, certData);

        // When/Then
        assertThat(verifier.hasTlsaRecord(TEST_HOSTNAME, 443)).isTrue();
    }

    @Test
    @DisplayName("hasTlsaRecord should return false when no record exists")
    void hasTlsaRecordShouldReturnFalseWhenNotExists() throws Exception {
        // Given
        EmptyResultVerifier verifier = new EmptyResultVerifier(createConfig());

        // When/Then
        assertThat(verifier.hasTlsaRecord(TEST_HOSTNAME, 443)).isFalse();
    }

    // ==================== Validation Mode Tests ====================

    @Test
    @DisplayName("Should use TRUST_RESOLVER mode by default")
    void shouldUseTrustResolverModeByDefault() {
        // Given
        DaneConfig config = DaneConfig.defaults();

        // When
        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Then
        assertThat(verifier.getValidationMode()).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
    }

    @Test
    @DisplayName("Should respect VALIDATE_IN_CODE mode")
    void shouldRespectValidateInCodeMode() {
        // Given
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.VALIDATE_IF_PRESENT)
            .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
            .build();

        // When
        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Then
        assertThat(verifier.getValidationMode()).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
    }

    // ==================== Helper Methods ====================

    private DaneConfig createConfig() {
        return DaneConfig.builder()
            .policy(DanePolicy.VALIDATE_IF_PRESENT)
            .cacheTtl(Duration.ZERO)
            .build();
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // ==================== Helper Classes ====================

    private record RecordInfo(int usage, int selector, int matchingType, byte[] certData) {}

    /**
     * Verifier that returns a single configured TLSA record.
     */
    private static class SingleRecordVerifier extends DefaultDaneTlsaVerifier {
        private final int usage;
        private final int selector;
        private final int matchingType;
        private final byte[] certData;

        SingleRecordVerifier(DaneConfig config, int usage, int selector, int matchingType, byte[] certData) {
            super(config);
            this.usage = usage;
            this.selector = selector;
            this.matchingType = matchingType;
            this.certData = certData;
        }

        @Override
        protected List<TlsaRecordData> performDnsLookup(String hostname, int port) {
            return List.of(new TlsaRecordData(usage, selector, matchingType, certData));
        }
    }

    /**
     * Verifier that returns multiple configured TLSA records.
     */
    private static class MultiRecordVerifier extends DefaultDaneTlsaVerifier {
        private final List<RecordInfo> records;

        MultiRecordVerifier(DaneConfig config, List<RecordInfo> records) {
            super(config);
            this.records = records;
        }

        @Override
        protected List<TlsaRecordData> performDnsLookup(String hostname, int port) {
            List<TlsaRecordData> result = new ArrayList<>();
            for (RecordInfo info : records) {
                result.add(new TlsaRecordData(info.usage, info.selector, info.matchingType, info.certData));
            }
            return result;
        }
    }

    /**
     * Verifier that returns no TLSA records.
     */
    private static class EmptyResultVerifier extends DefaultDaneTlsaVerifier {
        EmptyResultVerifier(DaneConfig config) {
            super(config);
        }

        @Override
        protected List<TlsaRecordData> performDnsLookup(String hostname, int port) {
            return List.of();
        }
    }

    /**
     * Verifier that counts DNS lookups for cache testing.
     */
    private static class CountingVerifier extends DefaultDaneTlsaVerifier {
        private int dnsLookupCount = 0;

        CountingVerifier(DaneConfig config) {
            super(config);
        }

        int getDnsLookupCount() {
            return dnsLookupCount;
        }

        @Override
        protected List<TlsaRecordData> performDnsLookup(String hostname, int port) {
            dnsLookupCount++;
            return List.of(); // Return empty for simplicity
        }
    }
}
