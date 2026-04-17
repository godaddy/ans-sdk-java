package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for TrustedDomainRegistry.
 *
 * <p><b>Note:</b> The trusted domains are captured once at class initialization
 * and cannot be changed afterward. Tests that need custom domains must be run
 * in a separate JVM with the system property set before class loading.</p>
 */
class TrustedDomainRegistryTest {

    @Nested
    @DisplayName("isTrustedDomain() with defaults")
    class DefaultDomainTests {

        @Test
        @DisplayName("Should accept production domain")
        void shouldAcceptProductionDomain() {
            assertThat(TrustedDomainRegistry.isTrustedDomain("transparency.ans.godaddy.com")).isTrue();
        }

        @Test
        @DisplayName("Should accept OTE domain")
        void shouldAcceptOteDomain() {
            assertThat(TrustedDomainRegistry.isTrustedDomain("transparency.ans.ote-godaddy.com")).isTrue();
        }

        @Test
        @DisplayName("Should be case insensitive")
        void shouldBeCaseInsensitive() {
            assertThat(TrustedDomainRegistry.isTrustedDomain("TRANSPARENCY.ANS.GODADDY.COM")).isTrue();
            assertThat(TrustedDomainRegistry.isTrustedDomain("Transparency.Ans.Godaddy.Com")).isTrue();
        }

        @Test
        @DisplayName("Should reject unknown domains")
        void shouldRejectUnknownDomains() {
            assertThat(TrustedDomainRegistry.isTrustedDomain("unknown.example.com")).isFalse();
            assertThat(TrustedDomainRegistry.isTrustedDomain("transparency.ans.evil.com")).isFalse();
        }

        @Test
        @DisplayName("Should reject null")
        void shouldRejectNull() {
            assertThat(TrustedDomainRegistry.isTrustedDomain(null)).isFalse();
        }

        @Test
        @DisplayName("Should reject empty string")
        void shouldRejectEmptyString() {
            assertThat(TrustedDomainRegistry.isTrustedDomain("")).isFalse();
        }
    }

    @Nested
    @DisplayName("Immutability guarantees")
    class ImmutabilityTests {

        @Test
        @DisplayName("getTrustedDomains() should return same instance on repeated calls")
        void shouldReturnSameInstance() {
            Set<String> first = TrustedDomainRegistry.getTrustedDomains();
            Set<String> second = TrustedDomainRegistry.getTrustedDomains();

            // Same reference - not just equal, but identical
            assertThat(first).isSameAs(second);
        }

        @Test
        @DisplayName("Returned set should be unmodifiable")
        void returnedSetShouldBeUnmodifiable() {
            Set<String> domains = TrustedDomainRegistry.getTrustedDomains();

            assertThatThrownBy(() -> domains.add("malicious.com"))
                .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("Runtime system property changes should NOT affect trusted domains")
        void runtimePropertyChangesShouldNotAffect() {
            // Capture current state
            Set<String> before = TrustedDomainRegistry.getTrustedDomains();
            boolean productionWasTrusted = TrustedDomainRegistry.isTrustedDomain("transparency.ans.godaddy.com");

            // Attempt to add a malicious domain via system property
            String originalValue = System.getProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY);
            try {
                System.setProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY, "malicious.attacker.com");

                // Verify the change had NO effect (security guarantee)
                Set<String> after = TrustedDomainRegistry.getTrustedDomains();
                assertThat(after).isSameAs(before);
                assertThat(TrustedDomainRegistry.isTrustedDomain("malicious.attacker.com")).isFalse();
                assertThat(TrustedDomainRegistry.isTrustedDomain("transparency.ans.godaddy.com"))
                    .isEqualTo(productionWasTrusted);
            } finally {
                // Restore original state
                if (originalValue == null) {
                    System.clearProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY);
                } else {
                    System.setProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY, originalValue);
                }
            }
        }

        @Test
        @DisplayName("Clearing system property at runtime should NOT affect trusted domains")
        void clearingPropertyShouldNotAffect() {
            // Capture current state
            Set<String> before = TrustedDomainRegistry.getTrustedDomains();

            // Attempt to clear the property
            String originalValue = System.getProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY);
            try {
                System.clearProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY);

                // Verify the change had NO effect
                Set<String> after = TrustedDomainRegistry.getTrustedDomains();
                assertThat(after).isSameAs(before);
            } finally {
                // Restore original state
                if (originalValue != null) {
                    System.setProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY, originalValue);
                }
            }
        }
    }

    @Nested
    @DisplayName("Default domain set constants")
    class DefaultSetTests {

        @Test
        @DisplayName("DEFAULT_TRUSTED_DOMAINS should be immutable")
        void defaultDomainsShouldBeImmutable() {
            assertThat(TrustedDomainRegistry.DEFAULT_TRUSTED_DOMAINS).isUnmodifiable();
        }

        @Test
        @DisplayName("Should contain expected default domains")
        void shouldContainExpectedDefaultDomains() {
            assertThat(TrustedDomainRegistry.DEFAULT_TRUSTED_DOMAINS)
                .hasSize(2)
                .contains("transparency.ans.godaddy.com", "transparency.ans.ote-godaddy.com");
        }

        @Test
        @DisplayName("DEFAULT_TRUSTED_DOMAINS constant should not be modifiable")
        void defaultConstantShouldNotBeModifiable() {
            assertThatThrownBy(() -> TrustedDomainRegistry.DEFAULT_TRUSTED_DOMAINS.add("attack.com"))
                .isInstanceOf(UnsupportedOperationException.class);
        }
    }
}
