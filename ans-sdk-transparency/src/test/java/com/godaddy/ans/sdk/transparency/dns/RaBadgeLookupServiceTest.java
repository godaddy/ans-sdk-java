package com.godaddy.ans.sdk.transparency.dns;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RaBadgeLookupService}.
 *
 * <p>These tests use a testable subclass that simulates DNS responses
 * without making actual network calls.</p>
 */
class RaBadgeLookupServiceTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    // Use valid UUID-format hex patterns (AGENT_ID_PATTERN matches [a-f0-9-]+)
    private static final String TEST_AGENT_ID_ANS = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_AGENT_ID_RA = "7cf3c8b0-2494-5f44-b056-956f45bf8637";

    // ==================== _ans-badge Priority Tests ====================

    @Test
    @DisplayName("Should prioritize _ans-badge when both _ans-badge and _ra-badge exist")
    void shouldPrioritizeAnsBadgeWhenBothExist() {
        // Given - both _ans-badge and _ra-badge records exist
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ans-badge." + TEST_HOSTNAME,
            "v=ans-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_ANS);
        dnsRecords.put("_ra-badge." + TEST_HOSTNAME,
            "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_RA);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        // When
        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        // Then - _ans-badge should be prioritized
        assertThat(badges).isNotEmpty();
        assertThat(badges.get(0).agentId()).isEqualTo(TEST_AGENT_ID_ANS);
        assertThat(badges.get(0).badgeVersion()).isEqualTo("ans-badge1");
    }

    @Test
    @DisplayName("Should use _ans-badge when only _ans-badge exists")
    void shouldUseAnsBadgeWhenOnlyAnsBadgeExists() {
        // Given - only _ans-badge record exists
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ans-badge." + TEST_HOSTNAME,
            "v=ans-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_ANS);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        // When
        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        // Then
        assertThat(badges).hasSize(1);
        assertThat(badges.get(0).agentId()).isEqualTo(TEST_AGENT_ID_ANS);
        assertThat(badges.get(0).badgeVersion()).isEqualTo("ans-badge1");
    }

    @Test
    @DisplayName("Should fallback to _ra-badge when no _ans-badge exists")
    void shouldFallbackToRaBadgeWhenNoAnsBadgeExists() {
        // Given - only _ra-badge record exists (backward compatibility)
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ra-badge." + TEST_HOSTNAME,
            "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_RA);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        // When
        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        // Then
        assertThat(badges).hasSize(1);
        assertThat(badges.get(0).agentId()).isEqualTo(TEST_AGENT_ID_RA);
        assertThat(badges.get(0).badgeVersion()).isEqualTo("ra-badge1");
    }

    @Test
    @DisplayName("Should return empty when neither _ans-badge nor _ra-badge exists")
    void shouldReturnEmptyWhenNeitherBadgeExists() {
        // Given - no badge records exist
        Map<String, String> dnsRecords = new HashMap<>();

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        // When
        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        // Then
        assertThat(badges).isEmpty();
    }

    @Test
    @DisplayName("lookupBadge() should return _ans-badge when both exist")
    void lookupBadgeShouldReturnAnsBadgeWhenBothExist() {
        // Given - both _ans-badge and _ra-badge records exist
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ans-badge." + TEST_HOSTNAME,
            "v=ans-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_ANS);
        dnsRecords.put("_ra-badge." + TEST_HOSTNAME,
            "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_RA);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        // When
        RaBadgeRecord badge = service.lookupBadge(TEST_HOSTNAME);

        // Then - should return _ans-badge (first/priority)
        assertThat(badge).isNotNull();
        assertThat(badge.agentId()).isEqualTo(TEST_AGENT_ID_ANS);
    }

    @Test
    @DisplayName("hasBadgeRecord() should return true when _ans-badge exists")
    void hasBadgeRecordShouldReturnTrueWhenAnsBadgeExists() {
        // Given - only _ans-badge exists
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ans-badge." + TEST_HOSTNAME,
            "v=ans-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_ANS);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        // When
        boolean hasBadge = service.hasBadgeRecord(TEST_HOSTNAME);

        // Then
        assertThat(hasBadge).isTrue();
    }

    @Test
    @DisplayName("hasBadgeRecord() should return true when only _ra-badge exists")
    void hasBadgeRecordShouldReturnTrueWhenOnlyRaBadgeExists() {
        // Given - only _ra-badge exists (backward compatibility)
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ra-badge." + TEST_HOSTNAME,
            "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_RA);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        // When
        boolean hasBadge = service.hasBadgeRecord(TEST_HOSTNAME);

        // Then
        assertThat(hasBadge).isTrue();
    }

    // ==================== Additional Edge Cases ====================

    @Test
    @DisplayName("lookupBadges should return empty list for null hostname")
    void lookupBadgesShouldReturnEmptyListForNullHostname() {
        Map<String, String> dnsRecords = new HashMap<>();
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        List<RaBadgeRecord> badges = service.lookupBadges(null);

        assertThat(badges).isEmpty();
    }

    @Test
    @DisplayName("lookupBadges should return empty list for blank hostname")
    void lookupBadgesShouldReturnEmptyListForBlankHostname() {
        Map<String, String> dnsRecords = new HashMap<>();
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        List<RaBadgeRecord> badges = service.lookupBadges("   ");

        assertThat(badges).isEmpty();
    }

    @Test
    @DisplayName("lookupBadge should return null when no badges exist")
    void lookupBadgeShouldReturnNullWhenNoBadgesExist() {
        Map<String, String> dnsRecords = new HashMap<>();
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        RaBadgeRecord badge = service.lookupBadge(TEST_HOSTNAME);

        assertThat(badge).isNull();
    }

    @Test
    @DisplayName("hasBadgeRecord should return false when no badges exist")
    void hasBadgeRecordShouldReturnFalseWhenNoBadgesExist() {
        Map<String, String> dnsRecords = new HashMap<>();
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        boolean hasBadge = service.hasBadgeRecord(TEST_HOSTNAME);

        assertThat(hasBadge).isFalse();
    }

    @Test
    @DisplayName("lookupBadges should normalize hostname with trailing dot")
    void lookupBadgesShouldNormalizeHostnameWithTrailingDot() {
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ans-badge." + TEST_HOSTNAME,
            "v=ans-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_ANS);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        // Query with trailing dot
        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME + ".");

        assertThat(badges).hasSize(1);
        assertThat(badges.get(0).agentId()).isEqualTo(TEST_AGENT_ID_ANS);
    }

    @Test
    @DisplayName("lookupBadges should combine all badges from both prefixes")
    void lookupBadgesShouldCombineAllBadgesFromBothPrefixes() {
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ans-badge." + TEST_HOSTNAME,
            "v=ans-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_ANS);
        dnsRecords.put("_ra-badge." + TEST_HOSTNAME,
            "v=ra-badge1; version=2.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_RA);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        // Should have both badges (_ans-badge first, then _ra-badge)
        assertThat(badges).hasSize(2);
    }

    @Test
    @DisplayName("lookupBadges should filter out invalid badge formats")
    void lookupBadgesShouldFilterOutInvalidBadgeFormats() {
        Map<String, String> dnsRecords = new HashMap<>();
        // This has unsupported badge format
        dnsRecords.put("_ans-badge." + TEST_HOSTNAME,
            "v=unsupported-format; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_ANS);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        // Should filter out unsupported formats
        assertThat(badges).isEmpty();
    }

    @Test
    @DisplayName("lookupBadges should handle multiple TXT records for same prefix")
    void lookupBadgesShouldHandleMultipleTxtRecordsForSamePrefix() {
        // TestableRaBadgeLookupService that supports multiple records per DNS name
        TestableRaBadgeLookupServiceMultiple service = new TestableRaBadgeLookupServiceMultiple();
        service.addRecord("_ans-badge." + TEST_HOSTNAME,
            "v=ans-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_ANS);
        service.addRecord("_ans-badge." + TEST_HOSTNAME,
            "v=ans-badge1; version=2.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_RA);

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        assertThat(badges).hasSize(2);
    }

    @Test
    @DisplayName("Should handle lookup exception gracefully")
    void shouldHandleLookupExceptionGracefully() {
        TestableRaBadgeLookupServiceWithException service = new TestableRaBadgeLookupServiceWithException();

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        assertThat(badges).isEmpty();
    }

    @Test
    @DisplayName("Should create service with default constructor")
    void shouldCreateServiceWithDefaultConstructor() {
        RaBadgeLookupService service = new RaBadgeLookupService();

        // Just verify it creates without exception
        assertThat(service).isNotNull();
    }

    @Test
    @DisplayName("Should create service with custom DNS server")
    void shouldCreateServiceWithCustomDnsServer() {
        RaBadgeLookupService service = new RaBadgeLookupService("8.8.8.8", Duration.ofSeconds(10));

        // Just verify it creates without exception
        assertThat(service).isNotNull();
    }

    // ==================== Testable Subclasses ====================

    /**
     * Test double for RaBadgeLookupService that uses in-memory DNS records
     * instead of making actual DNS queries.
     */
    private static class TestableRaBadgeLookupService extends RaBadgeLookupService {

        private final Map<String, String> mockDnsRecords;

        TestableRaBadgeLookupService(Map<String, String> mockDnsRecords) {
            super(null, Duration.ofSeconds(1));
            this.mockDnsRecords = mockDnsRecords;
        }

        /**
         * Override to return mock DNS records instead of making real queries.
         */
        @Override
        protected List<String> lookupTxtRecords(String dnsName) {
            String record = mockDnsRecords.get(dnsName);
            if (record != null) {
                return List.of(record);
            }
            return List.of();
        }
    }

    /**
     * Test double that supports multiple records per DNS name.
     */
    private static class TestableRaBadgeLookupServiceMultiple extends RaBadgeLookupService {

        private final Map<String, List<String>> mockDnsRecords = new HashMap<>();

        TestableRaBadgeLookupServiceMultiple() {
            super(null, Duration.ofSeconds(1));
        }

        void addRecord(String dnsName, String record) {
            mockDnsRecords.computeIfAbsent(dnsName, k -> new ArrayList<>()).add(record);
        }

        @Override
        protected List<String> lookupTxtRecords(String dnsName) {
            return mockDnsRecords.getOrDefault(dnsName, List.of());
        }
    }

    /**
     * Test double that throws exception during lookup.
     */
    private static class TestableRaBadgeLookupServiceWithException extends RaBadgeLookupService {

        TestableRaBadgeLookupServiceWithException() {
            super(null, Duration.ofSeconds(1));
        }

        @Override
        protected List<String> lookupTxtRecords(String dnsName) {
            throw new RuntimeException("Simulated DNS lookup failure");
        }
    }
}
