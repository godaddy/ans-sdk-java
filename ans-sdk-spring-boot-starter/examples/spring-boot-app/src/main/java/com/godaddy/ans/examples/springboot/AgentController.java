package com.godaddy.ans.examples.springboot;

import com.godaddy.ans.sdk.discovery.DiscoveryClient;
import com.godaddy.ans.sdk.model.generated.AgentDetails;
import com.godaddy.ans.sdk.model.generated.AgentRegistrationRequest;
import com.godaddy.ans.sdk.registration.RegistrationClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Example REST controller demonstrating injected ANS SDK beans.
 *
 * <p>Both {@link RegistrationClient} and {@link DiscoveryClient} are
 * auto-configured by the starter and injected via constructor.</p>
 */
@RestController
@RequestMapping("/api/agents")
public class AgentController {

    private final RegistrationClient registrationClient;
    private final DiscoveryClient discoveryClient;

    public AgentController(RegistrationClient registrationClient,
                           DiscoveryClient discoveryClient) {
        this.registrationClient = registrationClient;
        this.discoveryClient = discoveryClient;
    }

    /**
     * Registers a new agent.
     *
     * <pre>
     * POST /api/agents/register
     * {"agentHost": "my-agent.example.com", "agentVersion": "1.0.0"}
     * </pre>
     */
    @PostMapping("/register")
    public ResponseEntity<AgentDetails> register(@RequestBody AgentRegistrationRequest request) {
        AgentDetails agent = registrationClient.registerAgent(request);
        return ResponseEntity.ok(agent);
    }

    /**
     * Resolves an agent by host.
     *
     * <pre>
     * GET /api/agents/resolve?agentHost=my-agent.example.com
     * GET /api/agents/resolve?agentHost=my-agent.example.com&amp;version=^1.0.0
     * </pre>
     */
    @GetMapping("/resolve")
    public ResponseEntity<AgentDetails> resolve(
            @RequestParam String agentHost,
            @RequestParam(required = false) String version) {
        AgentDetails agent = discoveryClient.resolve(agentHost, version);
        return ResponseEntity.ok(agent);
    }

    /**
     * Health check showing the auto-configured environment.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "environment", registrationClient.getConfiguration().getEnvironment().name()
        ));
    }
}
