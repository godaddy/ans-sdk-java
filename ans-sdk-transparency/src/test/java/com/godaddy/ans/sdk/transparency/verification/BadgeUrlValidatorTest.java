package com.godaddy.ans.sdk.transparency.verification;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link BadgeUrlValidator}.
 */
class BadgeUrlValidatorTest {

    private static final String VALID_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";

    private BadgeUrlValidator validator;

    @BeforeEach
    void setUp() {
        validator = BadgeUrlValidator.withGoDaddyDefaults();
    }

    // ==================== Builder Tests ====================

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should create validator with custom domain")
        void shouldCreateValidatorWithCustomDomain() {
            BadgeUrlValidator customValidator = BadgeUrlValidator.builder()
                .addTrustedDomain("transparency.custom-provider.com")
                .build();

            String url = "https://transparency.custom-provider.com/v1/agents/" + VALID_AGENT_ID;
            BadgeUrlValidator.ValidationResult result = customValidator.validate(url);

            assertThat(result.valid()).isTrue();
        }

        @Test
        @DisplayName("Should reject untrusted domain with custom validator")
        void shouldRejectUntrustedDomainWithCustomValidator() {
            BadgeUrlValidator customValidator = BadgeUrlValidator.builder()
                .addTrustedDomain("transparency.my-provider.com")
                .build();

            // GoDaddy domain should be rejected since we didn't include it
            String url = "https://transparency.ans.godaddy.com/v1/agents/" + VALID_AGENT_ID;
            BadgeUrlValidator.ValidationResult result = customValidator.validate(url);

            assertThat(result.valid()).isFalse();
            assertThat(result.reason()).containsIgnoringCase("untrusted");
        }

        @Test
        @DisplayName("Should support multiple custom domains")
        void shouldSupportMultipleCustomDomains() {
            BadgeUrlValidator customValidator = BadgeUrlValidator.builder()
                .addTrustedDomain("transparency.provider1.com")
                .addTrustedDomain("transparency.provider2.com")
                .build();

            assertThat(customValidator.getTrustedDomains()).hasSize(2);
            assertThat(customValidator.getTrustedDomains()).contains(
                "transparency.provider1.com",
                "transparency.provider2.com"
            );
        }

        @Test
        @DisplayName("Should support adding domains from list")
        void shouldSupportAddingDomainsFromList() {
            List<String> domains = List.of("provider1.com", "provider2.com");
            BadgeUrlValidator customValidator = BadgeUrlValidator.builder()
                .addTrustedDomains(domains)
                .build();

            assertThat(customValidator.getTrustedDomains()).hasSize(2);
        }

        @Test
        @DisplayName("Should support adding GoDaddy defaults via builder")
        void shouldSupportAddingGoDaddyDefaultsViaBuilder() {
            BadgeUrlValidator customValidator = BadgeUrlValidator.builder()
                .addGoDaddyDefaults()
                .addTrustedDomain("transparency.custom.com")
                .build();

            assertThat(customValidator.getTrustedDomains()).hasSize(3); // 2 GoDaddy + 1 custom
        }

        @Test
        @DisplayName("Should throw if no domains configured")
        void shouldThrowIfNoDomainsConfigured() {
            assertThatThrownBy(() -> BadgeUrlValidator.builder().build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("At least one trusted domain");
        }

        @Test
        @DisplayName("Should throw if domain is null")
        void shouldThrowIfDomainIsNull() {
            assertThatThrownBy(() -> BadgeUrlValidator.builder().addTrustedDomain(null))
                .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw if domain is blank")
        void shouldThrowIfDomainIsBlank() {
            assertThatThrownBy(() -> BadgeUrlValidator.builder().addTrustedDomain("   "))
                .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("withGoDaddyDefaults should create validator with GoDaddy domains")
        void withGoDaddyDefaultsShouldCreateValidatorWithGoDaddyDomains() {
            BadgeUrlValidator godaddyValidator = BadgeUrlValidator.withGoDaddyDefaults();

            assertThat(godaddyValidator.getTrustedDomains()).containsExactlyInAnyOrder(
                "transparency.ans.godaddy.com",
                "transparency.ans.ote-godaddy.com"
            );
        }

        @Test
        @DisplayName("Domains should be stored lowercase")
        void domainsShouldBeStoredLowercase() {
            BadgeUrlValidator customValidator = BadgeUrlValidator.builder()
                .addTrustedDomain("Transparency.PROVIDER.Com")
                .build();

            assertThat(customValidator.getTrustedDomains()).contains("transparency.provider.com");
        }
    }

    // ==================== Plain HTTP Rejection ====================

    @Test
    @DisplayName("Should reject badge URL using plain HTTP")
    void shouldRejectPlainHttpUrl() {
        // Given - HTTP URL (not HTTPS)
        String url = "http://transparency.ans.godaddy.com/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).containsIgnoringCase("HTTPS");
    }

    @Test
    @DisplayName("Should accept HTTPS URL")
    void shouldAcceptHttpsUrl() {
        // Given - HTTPS URL
        String url = "https://transparency.ans.godaddy.com/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should accept
        assertThat(result.valid()).isTrue();
    }

    @Test
    @DisplayName("Should reject HTTP even for localhost")
    void shouldRejectHttpForLocalhost() {
        // Given - HTTP localhost URL (no longer allowed)
        String url = "http://localhost:11400/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject (HTTPS required, no localhost exception)
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).containsIgnoringCase("HTTPS required");
    }

    // ==================== Untrusted Domain Rejection ====================

    @Test
    @DisplayName("Should reject badge URL from untrusted domain")
    void shouldRejectUntrustedDomain() {
        // Given - URL with untrusted domain
        String url = "https://evil-transparency.attacker.com/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).containsIgnoringCase("untrusted");
    }

    @Test
    @DisplayName("Should reject badge URL with similar-looking domain")
    void shouldRejectSimilarLookingDomain() {
        // Given - URL with domain that looks similar to trusted domain
        String url = "https://transparency.ans.godaddy.com.attacker.com/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject
        assertThat(result.valid()).isFalse();
    }

    // ==================== Trusted Domain Acceptance ====================

    @Test
    @DisplayName("Should accept badge URL from trusted RA domain (production)")
    void shouldAcceptTrustedDomainProduction() {
        // Given - production transparency log URL
        String url = "https://transparency.ans.godaddy.com/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should accept
        assertThat(result.valid()).isTrue();
    }

    @Test
    @DisplayName("Should accept badge URL from trusted RA domain (OTE)")
    void shouldAcceptTrustedDomainOte() {
        // Given - OTE transparency log URL
        String url = "https://transparency.ans.ote-godaddy.com/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should accept
        assertThat(result.valid()).isTrue();
    }

    // ==================== Non-Standard Port Rejection ====================

    @Test
    @DisplayName("Should reject badge URL with non-standard port")
    void shouldRejectNonStandardPort() {
        // Given - URL with non-standard port
        String url = "https://transparency.ans.godaddy.com:8443/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).containsIgnoringCase("port");
    }

    @Test
    @DisplayName("Should accept badge URL with explicit port 443")
    void shouldAcceptExplicitPort443() {
        // Given - URL with explicit standard HTTPS port
        String url = "https://transparency.ans.godaddy.com:443/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should accept (443 is standard HTTPS port)
        assertThat(result.valid()).isTrue();
    }

    @Test
    @DisplayName("Should reject localhost even with HTTPS")
    void shouldRejectLocalhostEvenWithHttps() {
        // Given - HTTPS localhost URL (no longer allowed - must be trusted domain)
        String url = "https://localhost/v1/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject (localhost is not a trusted domain)
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).containsIgnoringCase("untrusted");
    }

    // ==================== Path Traversal/Injection Rejection ====================

    @Test
    @DisplayName("Should reject badge URL with path traversal")
    void shouldRejectPathTraversal() {
        // Given - URL with path traversal attack
        String url = "https://transparency.ans.godaddy.com/v1/agents/../../admin";

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).containsIgnoringCase("path");
    }

    @Test
    @DisplayName("Should reject badge URL with query injection")
    void shouldRejectQueryInjection() {
        // Given - URL with query parameters (not expected in badge URLs)
        String url = "https://transparency.ans.godaddy.com/v1/agents/" + VALID_AGENT_ID + "?admin=true";

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).containsIgnoringCase("query");
    }

    @Test
    @DisplayName("Should reject badge URL with URL-encoded traversal")
    void shouldRejectUrlEncodedTraversal() {
        // Given - URL with URL-encoded path traversal
        String url = "https://transparency.ans.godaddy.com/v1/agents/%2e%2e%2f%2e%2e%2fadmin";

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject
        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("Should reject badge URL with invalid path format")
    void shouldRejectInvalidPathFormat() {
        // Given - URL with path that doesn't match /v1/agents/{uuid}
        String url = "https://transparency.ans.godaddy.com/v2/agents/" + VALID_AGENT_ID;

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should reject (wrong API version)
        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("Should accept valid badge URL with trailing slash")
    void shouldAcceptValidUrlWithTrailingSlash() {
        // Given - valid URL with trailing slash
        String url = "https://transparency.ans.godaddy.com/v1/agents/" + VALID_AGENT_ID + "/";

        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(url);

        // Then - should accept
        assertThat(result.valid()).isTrue();
    }

    // ==================== Edge Cases ====================

    @Test
    @DisplayName("Should reject null URL")
    void shouldRejectNullUrl() {
        // When
        BadgeUrlValidator.ValidationResult result = validator.validate(null);

        // Then
        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("Should reject empty URL")
    void shouldRejectEmptyUrl() {
        // When
        BadgeUrlValidator.ValidationResult result = validator.validate("");

        // Then
        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("Should reject malformed URL")
    void shouldRejectMalformedUrl() {
        // When
        BadgeUrlValidator.ValidationResult result = validator.validate("not a url");

        // Then
        assertThat(result.valid()).isFalse();
    }
}
