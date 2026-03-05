package com.godaddy.ans.sdk.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for VerificationMode enum.
 */
class VerificationModeTest {

    @Test
    void enumHasThreeValues() {
        assertEquals(3, VerificationMode.values().length);
    }

    @Test
    void disabledExists() {
        assertEquals(VerificationMode.DISABLED, VerificationMode.valueOf("DISABLED"));
    }

    @Test
    void advisoryExists() {
        assertEquals(VerificationMode.ADVISORY, VerificationMode.valueOf("ADVISORY"));
    }

    @Test
    void requiredExists() {
        assertEquals(VerificationMode.REQUIRED, VerificationMode.valueOf("REQUIRED"));
    }

    @ParameterizedTest
    @EnumSource(VerificationMode.class)
    void allValuesAreNotNull(VerificationMode mode) {
        assertNotNull(mode);
        assertNotNull(mode.name());
    }

    @Test
    void ordinalValues() {
        assertEquals(0, VerificationMode.DISABLED.ordinal());
        assertEquals(1, VerificationMode.ADVISORY.ordinal());
        assertEquals(2, VerificationMode.REQUIRED.ordinal());
    }
}
