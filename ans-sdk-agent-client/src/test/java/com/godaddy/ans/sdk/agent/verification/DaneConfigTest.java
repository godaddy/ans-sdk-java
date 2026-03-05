package com.godaddy.ans.sdk.agent.verification;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for DaneConfig.
 */
class DaneConfigTest {

    @Test
    void defaultsCreatesValidConfig() {
        DaneConfig config = DaneConfig.defaults();

        assertNotNull(config);
        assertEquals(DanePolicy.VALIDATE_IF_PRESENT, config.policy());
        assertEquals(DnsResolverConfig.CLOUDFLARE, config.resolver());
        assertEquals(DnssecValidationMode.TRUST_RESOLVER, config.validationMode());
        assertEquals(DaneConfig.DEFAULT_CACHE_TTL, config.cacheTtl());
    }

    @Test
    void disabledCreatesDisabledConfig() {
        DaneConfig config = DaneConfig.disabled();

        assertEquals(DanePolicy.DISABLED, config.policy());
        assertEquals(DnsResolverConfig.SYSTEM, config.resolver());
        assertEquals(Duration.ZERO, config.cacheTtl());
    }

    @Test
    void builderWithAllOptions() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.REQUIRED)
            .resolver(DnsResolverConfig.GOOGLE)
            .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
            .cacheTtl(Duration.ofMinutes(30))
            .build();

        assertEquals(DanePolicy.REQUIRED, config.policy());
        assertEquals(DnsResolverConfig.GOOGLE, config.resolver());
        assertEquals(DnssecValidationMode.VALIDATE_IN_CODE, config.validationMode());
        assertEquals(Duration.ofMinutes(30), config.cacheTtl());
    }

    @Test
    void builderUsesDefaultValues() {
        DaneConfig config = DaneConfig.builder().build();

        assertEquals(DanePolicy.VALIDATE_IF_PRESENT, config.policy());
        assertEquals(DnsResolverConfig.CLOUDFLARE, config.resolver());
        assertEquals(DnssecValidationMode.TRUST_RESOLVER, config.validationMode());
        assertEquals(DaneConfig.DEFAULT_CACHE_TTL, config.cacheTtl());
    }

    @Test
    void constructorRejectsNullPolicy() {
        assertThrows(NullPointerException.class, () ->
            new DaneConfig(null, DnsResolverConfig.CLOUDFLARE, DnssecValidationMode.TRUST_RESOLVER,
                    Duration.ofHours(1)));
    }

    @Test
    void constructorRejectsNullResolver() {
        assertThrows(NullPointerException.class, () ->
            new DaneConfig(DanePolicy.REQUIRED, null, DnssecValidationMode.TRUST_RESOLVER, Duration.ofHours(1)));
    }

    @Test
    void constructorRejectsNullValidationMode() {
        assertThrows(NullPointerException.class, () ->
            new DaneConfig(DanePolicy.REQUIRED, DnsResolverConfig.CLOUDFLARE, null, Duration.ofHours(1)));
    }

    @Test
    void constructorRejectsNullCacheTtl() {
        assertThrows(NullPointerException.class, () ->
            new DaneConfig(DanePolicy.REQUIRED, DnsResolverConfig.CLOUDFLARE, DnssecValidationMode.TRUST_RESOLVER,
                    null));
    }

    @Test
    void constructorRejectsNegativeCacheTtl() {
        assertThrows(IllegalArgumentException.class, () ->
            new DaneConfig(DanePolicy.REQUIRED, DnsResolverConfig.CLOUDFLARE, DnssecValidationMode.TRUST_RESOLVER,
                    Duration.ofMinutes(-1)));
    }

    @Test
    void builderRejectsNullPolicy() {
        assertThrows(NullPointerException.class, () ->
            DaneConfig.builder().policy(null));
    }

    @Test
    void builderRejectsNullResolver() {
        assertThrows(NullPointerException.class, () ->
            DaneConfig.builder().resolver(null));
    }

    @Test
    void builderRejectsNullValidationMode() {
        assertThrows(NullPointerException.class, () ->
            DaneConfig.builder().validationMode(null));
    }

    @Test
    void builderRejectsNullCacheTtl() {
        assertThrows(NullPointerException.class, () ->
            DaneConfig.builder().cacheTtl(null));
    }

    @Test
    void zeroCacheTtlDisablesCaching() {
        DaneConfig config = DaneConfig.builder()
            .cacheTtl(Duration.ZERO)
            .build();

        assertEquals(Duration.ZERO, config.cacheTtl());
    }

    @Test
    void builderMethodsReturnBuilder() {
        DaneConfig.Builder builder = DaneConfig.builder();

        assertSame(builder, builder.policy(DanePolicy.REQUIRED));
        assertSame(builder, builder.resolver(DnsResolverConfig.QUAD9));
        assertSame(builder, builder.validationMode(DnssecValidationMode.VALIDATE_IN_CODE));
        assertSame(builder, builder.cacheTtl(Duration.ofMinutes(15)));
    }

    @Test
    void allDnsResolverConfigs() {
        for (DnsResolverConfig resolver : DnsResolverConfig.values()) {
            DaneConfig config = DaneConfig.builder()
                .resolver(resolver)
                .build();

            assertEquals(resolver, config.resolver());
        }
    }

    @Test
    void allDanePolicies() {
        for (DanePolicy policy : DanePolicy.values()) {
            DaneConfig config = DaneConfig.builder()
                .policy(policy)
                .build();

            assertEquals(policy, config.policy());
        }
    }

    @Test
    void allValidationModes() {
        for (DnssecValidationMode mode : DnssecValidationMode.values()) {
            DaneConfig config = DaneConfig.builder()
                .validationMode(mode)
                .build();

            assertEquals(mode, config.validationMode());
        }
    }

    @Test
    void defaultCacheTtlConstant() {
        assertEquals(Duration.ofHours(1), DaneConfig.DEFAULT_CACHE_TTL);
    }
}
