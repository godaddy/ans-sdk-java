package com.godaddy.ans.sdk.agent.verification;

import org.xbill.DNS.SimpleResolver;

import java.net.UnknownHostException;

/**
 * Factory for creating DNS resolvers.
 *
 * <p>This interface allows for dependency injection of resolver creation,
 * making it easier to test DNS-related code without making real network calls.</p>
 */
@FunctionalInterface
public interface ResolverFactory {

    /**
     * Creates a SimpleResolver for DNS queries.
     *
     * @param dnsServer the DNS server address, or null for system default
     * @return a configured SimpleResolver
     * @throws UnknownHostException if the DNS server address is invalid
     */
    SimpleResolver create(String dnsServer) throws UnknownHostException;

    /**
     * Returns the default factory that creates real SimpleResolver instances.
     *
     * @return the default resolver factory
     */
    static ResolverFactory defaultFactory() {
        return DefaultResolverFactory.INSTANCE;
    }
}
