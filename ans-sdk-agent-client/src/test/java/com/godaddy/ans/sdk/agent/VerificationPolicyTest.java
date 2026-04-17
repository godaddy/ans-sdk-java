package com.godaddy.ans.sdk.agent;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for VerificationPolicy.
 */
class VerificationPolicyTest {

    @Test
    void pkiOnlyHasNoVerification() {
        assertFalse(VerificationPolicy.PKI_ONLY.hasAnyVerification());
        assertEquals(VerificationMode.DISABLED, VerificationPolicy.PKI_ONLY.daneMode());
        assertEquals(VerificationMode.DISABLED, VerificationPolicy.PKI_ONLY.badgeMode());
    }

    @Test
    void badgeRequiredHasBadgeOnly() {
        assertTrue(VerificationPolicy.BADGE_REQUIRED.hasAnyVerification());
        assertEquals(VerificationMode.DISABLED, VerificationPolicy.BADGE_REQUIRED.daneMode());
        assertEquals(VerificationMode.REQUIRED, VerificationPolicy.BADGE_REQUIRED.badgeMode());
    }

    @Test
    void daneAdvisoryHasDaneAdvisory() {
        assertTrue(VerificationPolicy.DANE_ADVISORY.hasAnyVerification());
        assertEquals(VerificationMode.ADVISORY, VerificationPolicy.DANE_ADVISORY.daneMode());
        assertEquals(VerificationMode.DISABLED, VerificationPolicy.DANE_ADVISORY.badgeMode());
    }

    @Test
    void daneRequiredHasDaneRequired() {
        assertTrue(VerificationPolicy.DANE_REQUIRED.hasAnyVerification());
        assertEquals(VerificationMode.REQUIRED, VerificationPolicy.DANE_REQUIRED.daneMode());
        assertEquals(VerificationMode.DISABLED, VerificationPolicy.DANE_REQUIRED.badgeMode());
    }

    @Test
    void daneAndBadgeHasBothRequired() {
        assertTrue(VerificationPolicy.DANE_AND_BADGE.hasAnyVerification());
        assertEquals(VerificationMode.REQUIRED, VerificationPolicy.DANE_AND_BADGE.daneMode());
        assertEquals(VerificationMode.REQUIRED, VerificationPolicy.DANE_AND_BADGE.badgeMode());
    }

    @Test
    void customBuilderDefaultsToDisabled() {
        VerificationPolicy policy = VerificationPolicy.custom().build();

        assertFalse(policy.hasAnyVerification());
        assertEquals(VerificationMode.DISABLED, policy.daneMode());
        assertEquals(VerificationMode.DISABLED, policy.badgeMode());
    }

    @Test
    void customBuilderWithDane() {
        VerificationPolicy policy = VerificationPolicy.custom()
            .dane(VerificationMode.REQUIRED)
            .build();

        assertTrue(policy.hasAnyVerification());
        assertEquals(VerificationMode.REQUIRED, policy.daneMode());
        assertEquals(VerificationMode.DISABLED, policy.badgeMode());
    }

    @Test
    void customBuilderWithBadge() {
        VerificationPolicy policy = VerificationPolicy.custom()
            .badge(VerificationMode.ADVISORY)
            .build();

        assertTrue(policy.hasAnyVerification());
        assertEquals(VerificationMode.DISABLED, policy.daneMode());
        assertEquals(VerificationMode.ADVISORY, policy.badgeMode());
    }

    @Test
    void customBuilderWithBothModes() {
        VerificationPolicy policy = VerificationPolicy.custom()
            .dane(VerificationMode.ADVISORY)
            .badge(VerificationMode.REQUIRED)
            .build();

        assertTrue(policy.hasAnyVerification());
        assertEquals(VerificationMode.ADVISORY, policy.daneMode());
        assertEquals(VerificationMode.REQUIRED, policy.badgeMode());
    }

    @Test
    void builderRejectsNullDaneMode() {
        assertThrows(NullPointerException.class, () ->
            VerificationPolicy.custom().dane(null));
    }

    @Test
    void builderRejectsNullBadgeMode() {
        assertThrows(NullPointerException.class, () ->
            VerificationPolicy.custom().badge(null));
    }

    @Test
    void builderMethodsReturnBuilder() {
        VerificationPolicy.Builder builder = VerificationPolicy.custom();

        assertSame(builder, builder.dane(VerificationMode.ADVISORY));
        assertSame(builder, builder.badge(VerificationMode.REQUIRED));
    }

    @Test
    void toStringContainsKeyInfo() {
        String str = VerificationPolicy.BADGE_REQUIRED.toString();

        assertTrue(str.contains("badge"));
        assertTrue(str.contains("dane"));
        assertTrue(str.contains("REQUIRED"));
        assertTrue(str.contains("DISABLED"));
    }

    @Test
    void hasAnyVerificationWithAdvisoryMode() {
        VerificationPolicy policy = VerificationPolicy.custom()
            .dane(VerificationMode.ADVISORY)
            .build();

        assertTrue(policy.hasAnyVerification());
    }

    @Test
    void presetPoliciesAreNotNull() {
        assertNotNull(VerificationPolicy.PKI_ONLY);
        assertNotNull(VerificationPolicy.BADGE_REQUIRED);
        assertNotNull(VerificationPolicy.DANE_ADVISORY);
        assertNotNull(VerificationPolicy.DANE_REQUIRED);
        assertNotNull(VerificationPolicy.DANE_AND_BADGE);
    }

    // Tests for allowsScittFallbackToBadge()

    @Test
    void scittEnhancedAllowsFallbackToBadge() {
        assertTrue(VerificationPolicy.SCITT_ENHANCED.allowsScittFallbackToBadge(),
            "SCITT_ENHANCED (scitt=REQUIRED, badge=ADVISORY) should allow fallback");
    }

    @Test
    void scittRequiredDoesNotAllowFallbackToBadge() {
        assertFalse(VerificationPolicy.SCITT_REQUIRED.allowsScittFallbackToBadge(),
            "SCITT_REQUIRED (badge=DISABLED) should not allow fallback");
    }

    @Test
    void badgeRequiredDoesNotAllowFallbackToBadge() {
        assertFalse(VerificationPolicy.BADGE_REQUIRED.allowsScittFallbackToBadge(),
            "BADGE_REQUIRED (scitt=DISABLED) should not allow fallback");
    }

    @Test
    void customPolicyWithScittRequiredAndBadgeRequiredDoesNotAllowFallback() {
        VerificationPolicy policy = VerificationPolicy.custom()
            .scitt(VerificationMode.REQUIRED)
            .badge(VerificationMode.REQUIRED)
            .build();

        assertFalse(policy.allowsScittFallbackToBadge(),
            "When both SCITT and Badge are REQUIRED, no fallback should be allowed");
    }

    @Test
    void customPolicyWithScittAdvisoryDoesNotAllowFallback() {
        VerificationPolicy policy = VerificationPolicy.custom()
            .scitt(VerificationMode.ADVISORY)
            .badge(VerificationMode.ADVISORY)
            .build();

        assertFalse(policy.allowsScittFallbackToBadge(),
            "SCITT ADVISORY mode should not allow fallback (must be REQUIRED)");
    }

    // Tests for rejectsInvalidScittHeaders()

    @Test
    void scittRequiredRejectsInvalidHeaders() {
        assertTrue(VerificationPolicy.SCITT_REQUIRED.rejectsInvalidScittHeaders(),
            "SCITT_REQUIRED should reject invalid headers");
    }

    @Test
    void scittEnhancedRejectsInvalidHeaders() {
        assertTrue(VerificationPolicy.SCITT_ENHANCED.rejectsInvalidScittHeaders(),
            "SCITT_ENHANCED should reject invalid headers");
    }

    @Test
    void badgeRequiredDoesNotRejectInvalidHeaders() {
        assertFalse(VerificationPolicy.BADGE_REQUIRED.rejectsInvalidScittHeaders(),
            "BADGE_REQUIRED (scitt=DISABLED) should not reject SCITT headers");
    }

    @Test
    void pkiOnlyDoesNotRejectInvalidHeaders() {
        assertFalse(VerificationPolicy.PKI_ONLY.rejectsInvalidScittHeaders(),
            "PKI_ONLY should not reject SCITT headers");
    }

    @Test
    void customPolicyWithScittAdvisoryRejectsInvalidHeaders() {
        VerificationPolicy policy = VerificationPolicy.custom()
            .scitt(VerificationMode.ADVISORY)
            .build();

        assertTrue(policy.rejectsInvalidScittHeaders(),
            "SCITT ADVISORY should still reject invalid headers when present");
    }
}
