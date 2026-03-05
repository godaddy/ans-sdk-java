package com.godaddy.ans.sdk.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for Environment enum.
 */
class EnvironmentTest {

    @Test
    @DisplayName("Should have correct base URL for OTE")
    void shouldHaveCorrectBaseUrlForOte() {
        assertThat(Environment.OTE.getBaseUrl()).isEqualTo("https://api.ote-godaddy.com");
    }

    @Test
    @DisplayName("Should have correct base URL for PROD")
    void shouldHaveCorrectBaseUrlForProd() {
        assertThat(Environment.PROD.getBaseUrl()).isEqualTo("https://api.godaddy.com");
    }

    @Test
    @DisplayName("Should have two environments defined")
    void shouldHaveTwoEnvironments() {
        assertThat(Environment.values()).hasSize(2);
    }

    @Test
    @DisplayName("Should be able to get environment by name")
    void shouldGetEnvironmentByName() {
        assertThat(Environment.valueOf("OTE")).isEqualTo(Environment.OTE);
        assertThat(Environment.valueOf("PROD")).isEqualTo(Environment.PROD);
    }

    @Test
    @DisplayName("Should find environment from base URL")
    void shouldFindEnvironmentFromBaseUrl() {
        assertThat(Environment.fromBaseUrl("https://api.ote-godaddy.com")).isEqualTo(Environment.OTE);
        assertThat(Environment.fromBaseUrl("https://api.godaddy.com")).isEqualTo(Environment.PROD);
    }

    @Test
    @DisplayName("Should throw exception for unknown base URL")
    void shouldThrowExceptionForUnknownBaseUrl() {
        assertThatThrownBy(() -> Environment.fromBaseUrl("https://unknown.com"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unknown environment");
    }
}