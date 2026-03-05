package com.godaddy.ans.sdk.transparency.dns;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RaBadgeRecordTest {

    @Test
    @DisplayName("Should parse valid ra-badge TXT record without agent version")
    void shouldParseValidRaBadgeRecordWithoutAgentVersion() {
        String txtValue = "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/6bf2b7a9-1383-4e33-a945-845f34af7526";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ra-badge1");
        assertThat(record.agentVersion()).isNull();
        assertThat(record.url()).isEqualTo("https://transparency.ans.godaddy.com/v1/agents/6bf2b7a9-1383-4e33-a945-845f34af7526");
        assertThat(record.agentId()).isEqualTo("6bf2b7a9-1383-4e33-a945-845f34af7526");
        assertThat(record.isSupportedBadgeFormat()).isTrue();
    }

    @Test
    @DisplayName("Should parse valid ra-badge TXT record with agent version")
    void shouldParseValidRaBadgeRecordWithAgentVersion() {
        String txtValue = "v=ra-badge1; version=1.2.3; url=https://transparency.ans.godaddy.com/v1/agents/6bf2b7a9-1383-4e33-a945-845f34af7526";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ra-badge1");
        assertThat(record.agentVersion()).isEqualTo("1.2.3");
        assertThat(record.url()).isEqualTo("https://transparency.ans.godaddy.com/v1/agents/6bf2b7a9-1383-4e33-a945-845f34af7526");
        assertThat(record.agentId()).isEqualTo("6bf2b7a9-1383-4e33-a945-845f34af7526");
        assertThat(record.isSupportedBadgeFormat()).isTrue();
    }

    @Test
    @DisplayName("Should parse ra-badge record without trailing slash")
    void shouldParseRecordWithoutTrailingSlash() {
        String txtValue = "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/abc-123";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.agentId()).isEqualTo("abc-123");
    }

    @Test
    @DisplayName("Should parse ra-badge record with trailing slash")
    void shouldParseRecordWithTrailingSlash() {
        String txtValue = "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/abc-123/";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.agentId()).isEqualTo("abc-123");
    }

    @Test
    @DisplayName("Should handle different badge format versions")
    void shouldHandleDifferentBadgeFormatVersions() {
        String txtValue = "v=ra-badge2; url=https://example.com/v1/agents/test-id";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ra-badge2");
        assertThat(record.isSupportedBadgeFormat()).isTrue();
    }

    @Test
    @DisplayName("Should be case insensitive")
    void shouldBeCaseInsensitive() {
        String txtValue = "V=RA-BADGE1; URL=https://transparency.ans.godaddy.com/V1/AGENTS/test-id";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("RA-BADGE1");
    }

    @Test
    @DisplayName("Should handle extra whitespace")
    void shouldHandleExtraWhitespace() {
        String txtValue = "  v=ra-badge1  ;  url=https://transparency.ans.godaddy.com/v1/agents/test-id  ";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ra-badge1");
    }

    @Test
    @DisplayName("Should return null for null input")
    void shouldReturnNullForNullInput() {
        RaBadgeRecord record = RaBadgeRecord.parse(null);

        assertThat(record).isNull();
    }

    @Test
    @DisplayName("Should return null for empty input")
    void shouldReturnNullForEmptyInput() {
        RaBadgeRecord record = RaBadgeRecord.parse("");

        assertThat(record).isNull();
    }

    @Test
    @DisplayName("Should return null for blank input")
    void shouldReturnNullForBlankInput() {
        RaBadgeRecord record = RaBadgeRecord.parse("   ");

        assertThat(record).isNull();
    }

    @Test
    @DisplayName("Should return null for invalid format")
    void shouldReturnNullForInvalidFormat() {
        RaBadgeRecord record = RaBadgeRecord.parse("not a valid ra-badge record");

        assertThat(record).isNull();
    }

    @Test
    @DisplayName("Should return null for missing url")
    void shouldReturnNullForMissingUrl() {
        RaBadgeRecord record = RaBadgeRecord.parse("v=ra-badge1");

        assertThat(record).isNull();
    }

    @Test
    @DisplayName("Should identify unsupported badge formats")
    void shouldIdentifyUnsupportedBadgeFormats() {
        String txtValue = "v=other-format; url=https://example.com/test";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.isSupportedBadgeFormat()).isFalse();
    }

    @Test
    @DisplayName("Should implement equals and hashCode")
    void shouldImplementEqualsAndHashCode() {
        String txtValue = "v=ra-badge1; url=https://example.com/v1/agents/test-id";

        RaBadgeRecord record1 = RaBadgeRecord.parse(txtValue);
        RaBadgeRecord record2 = RaBadgeRecord.parse(txtValue);

        assertThat(record1).isEqualTo(record2);
        assertThat(record1.hashCode()).isEqualTo(record2.hashCode());
    }

    @Test
    @DisplayName("Should have meaningful toString")
    void shouldHaveMeaningfulToString() {
        String txtValue = "v=ra-badge1; version=1.0.0; url=https://example.com/v1/agents/test-id";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record.toString())
            .contains("badgeVersion='ra-badge1'")
            .contains("agentVersion='1.0.0'")
            .contains("test-id");
    }

    @Test
    @DisplayName("Should parse with extra whitespace around version")
    void shouldParseWithWhitespaceAroundVersion() {
        String txtValue = "v=ra-badge1;  version=2.0.0  ;  url=https://example.com/v1/agents/abc-def-123";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ra-badge1");
        assertThat(record.agentVersion()).isEqualTo("2.0.0");
        assertThat(record.agentId()).isEqualTo("abc-def-123");
    }

    @Test
    @DisplayName("Should parse legacy ra-badge record with v=ra-badge1 format")
    void shouldParseLegacyRaBadgeWithRaBadge1Format() {
        String txtValue = "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/6bf2b7a9-1383-4e33-a945-845f34af7526";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ra-badge1");
        assertThat(record.agentVersion()).isEqualTo("1.0.0");
        assertThat(record.agentId()).isEqualTo("6bf2b7a9-1383-4e33-a945-845f34af7526");
        assertThat(record.isSupportedBadgeFormat()).isTrue();
    }

    @Test
    @DisplayName("Should parse legacy ra-badge record without version field")
    void shouldParseLegacyRaBadgeWithoutVersionField() {
        // Older ra-badge records may not have a version field
        String txtValue = "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/abc123-def456-789012";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ra-badge1");
        assertThat(record.agentVersion()).isNull(); // No version in legacy records
        assertThat(record.agentId()).isEqualTo("abc123-def456-789012");
        assertThat(record.isSupportedBadgeFormat()).isTrue();
    }

    @Test
    @DisplayName("Should accept bare semver without v prefix")
    void shouldAcceptBareSemverWithoutVPrefix() {
        // Legacy records may have bare semver (1.0.0) instead of v-prefixed (v1.0.0)
        // Note: The RaBadgeRecord stores the version as-is. Normalization to v-prefixed
        // format is expected to happen at the comparison level (BadgeVerificationService).
        String txtValue = "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/bare-semver-agent";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.agentVersion()).isEqualTo("1.0.0"); // Stored as-is
        // The comparison logic in BadgeVerificationService.extractVersionFromAnsName()
        // handles the v prefix when matching versions
    }

    @Test
    @DisplayName("Should accept v-prefixed semver")
    void shouldAcceptVPrefixedSemver() {
        // Modern records should have v-prefixed version
        String txtValue = "v=ra-badge1; version=v1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/v-prefixed-agent";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.agentVersion()).isEqualTo("v1.0.0");
    }

    @Test
    @DisplayName("Should support ans-badge format version")
    void shouldSupportAnsBadgeFormatVersion() {
        // Future: ans-badge format
        String txtValue = "v=ans-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/ans-badge-agent";

        RaBadgeRecord record = RaBadgeRecord.parse(txtValue);

        assertThat(record).isNotNull();
        assertThat(record.badgeVersion()).isEqualTo("ans-badge1");
        assertThat(record.agentVersion()).isEqualTo("1.0.0");
    }
}