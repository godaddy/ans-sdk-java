package com.godaddy.ans.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.SimpleResolver;

import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultResolverFactoryTest {

    @Test
    @DisplayName("INSTANCE is singleton")
    void instanceIsSingleton() {
        DefaultResolverFactory instance1 = DefaultResolverFactory.INSTANCE;
        DefaultResolverFactory instance2 = DefaultResolverFactory.INSTANCE;

        assertThat(instance1).isSameAs(instance2);
    }

    @Test
    @DisplayName("create() with DNS server address creates resolver")
    void createWithAddressCreatesResolver() throws UnknownHostException {
        SimpleResolver resolver = DefaultResolverFactory.INSTANCE.create("8.8.8.8");

        assertThat(resolver).isNotNull();
    }

    @Test
    @DisplayName("create() with null address creates default resolver")
    void createWithNullAddressCreatesDefaultResolver() throws UnknownHostException {
        SimpleResolver resolver = DefaultResolverFactory.INSTANCE.create(null);

        assertThat(resolver).isNotNull();
    }

    @Test
    @DisplayName("create() with blank address creates default resolver")
    void createWithBlankAddressCreatesDefaultResolver() throws UnknownHostException {
        SimpleResolver resolver = DefaultResolverFactory.INSTANCE.create("   ");

        assertThat(resolver).isNotNull();
    }

    @Test
    @DisplayName("create() with empty address creates default resolver")
    void createWithEmptyAddressCreatesDefaultResolver() throws UnknownHostException {
        SimpleResolver resolver = DefaultResolverFactory.INSTANCE.create("");

        assertThat(resolver).isNotNull();
    }
}
