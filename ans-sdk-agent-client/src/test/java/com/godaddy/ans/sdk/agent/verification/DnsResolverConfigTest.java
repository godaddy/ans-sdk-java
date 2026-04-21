package com.godaddy.ans.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DnsResolverConfigTest {

    @Test
    @DisplayName("SYSTEM has null addresses")
    void systemHasNullAddresses() {
        assertThat(DnsResolverConfig.SYSTEM.getPrimaryAddress()).isNull();
        assertThat(DnsResolverConfig.SYSTEM.getSecondaryAddress()).isNull();
    }

    @Test
    @DisplayName("SYSTEM.isSystemResolver() returns true")
    void systemIsSystemResolverReturnsTrue() {
        assertThat(DnsResolverConfig.SYSTEM.isSystemResolver()).isTrue();
    }

    @Test
    @DisplayName("CLOUDFLARE has correct addresses")
    void cloudflareHasCorrectAddresses() {
        assertThat(DnsResolverConfig.CLOUDFLARE.getPrimaryAddress()).isEqualTo("1.1.1.1");
        assertThat(DnsResolverConfig.CLOUDFLARE.getSecondaryAddress()).isEqualTo("1.0.0.1");
    }

    @Test
    @DisplayName("CLOUDFLARE.isSystemResolver() returns false")
    void cloudflareIsSystemResolverReturnsFalse() {
        assertThat(DnsResolverConfig.CLOUDFLARE.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("GOOGLE has correct addresses")
    void googleHasCorrectAddresses() {
        assertThat(DnsResolverConfig.GOOGLE.getPrimaryAddress()).isEqualTo("8.8.8.8");
        assertThat(DnsResolverConfig.GOOGLE.getSecondaryAddress()).isEqualTo("8.8.4.4");
    }

    @Test
    @DisplayName("GOOGLE.isSystemResolver() returns false")
    void googleIsSystemResolverReturnsFalse() {
        assertThat(DnsResolverConfig.GOOGLE.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("QUAD9 has correct addresses")
    void quad9HasCorrectAddresses() {
        assertThat(DnsResolverConfig.QUAD9.getPrimaryAddress()).isEqualTo("9.9.9.9");
        assertThat(DnsResolverConfig.QUAD9.getSecondaryAddress()).isEqualTo("149.112.112.112");
    }

    @Test
    @DisplayName("QUAD9.isSystemResolver() returns false")
    void quad9IsSystemResolverReturnsFalse() {
        assertThat(DnsResolverConfig.QUAD9.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("All values are present")
    void allValuesPresent() {
        assertThat(DnsResolverConfig.values()).hasSize(4);
        assertThat(DnsResolverConfig.values()).containsExactly(
            DnsResolverConfig.SYSTEM,
            DnsResolverConfig.CLOUDFLARE,
            DnsResolverConfig.GOOGLE,
            DnsResolverConfig.QUAD9
        );
    }

    @Test
    @DisplayName("valueOf works correctly")
    void valueOfWorksCorrectly() {
        assertThat(DnsResolverConfig.valueOf("SYSTEM")).isEqualTo(DnsResolverConfig.SYSTEM);
        assertThat(DnsResolverConfig.valueOf("CLOUDFLARE")).isEqualTo(DnsResolverConfig.CLOUDFLARE);
        assertThat(DnsResolverConfig.valueOf("GOOGLE")).isEqualTo(DnsResolverConfig.GOOGLE);
        assertThat(DnsResolverConfig.valueOf("QUAD9")).isEqualTo(DnsResolverConfig.QUAD9);
    }
}
