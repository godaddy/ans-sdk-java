package com.godaddy.ans.sdk.agent.verification;

import org.xbill.DNS.SimpleResolver;

import java.net.UnknownHostException;

/**
 * Default implementation of {@link ResolverFactory} that creates real SimpleResolver instances.
 */
public final class DefaultResolverFactory implements ResolverFactory {

    /**
     * Singleton instance.
     */
    public static final DefaultResolverFactory INSTANCE = new DefaultResolverFactory();

    private DefaultResolverFactory() {
        // Singleton
    }

    @Override
    public SimpleResolver create(String dnsServer) throws UnknownHostException {
        if (dnsServer != null && !dnsServer.isBlank()) {
            return new SimpleResolver(dnsServer);
        }
        return new SimpleResolver();
    }
}
