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
    void fullHasAllRequired() {
        assertTrue(VerificationPolicy.FULL.hasAnyVerification());
        assertEquals(VerificationMode.REQUIRED, VerificationPolicy.FULL.daneMode());
        assertEquals(VerificationMode.REQUIRED, VerificationPolicy.FULL.badgeMode());
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
    void constructorRejectsNullDaneMode() {
        assertThrows(NullPointerException.class, () ->
            new VerificationPolicy(null, VerificationMode.DISABLED));
    }

    @Test
    void constructorRejectsNullBadgeMode() {
        assertThrows(NullPointerException.class, () ->
            new VerificationPolicy(VerificationMode.DISABLED, null));
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
    void recordAccessors() {
        VerificationPolicy policy = new VerificationPolicy(
            VerificationMode.ADVISORY, VerificationMode.REQUIRED);

        assertEquals(VerificationMode.ADVISORY, policy.daneMode());
        assertEquals(VerificationMode.REQUIRED, policy.badgeMode());
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
        assertNotNull(VerificationPolicy.FULL);
    }
}
