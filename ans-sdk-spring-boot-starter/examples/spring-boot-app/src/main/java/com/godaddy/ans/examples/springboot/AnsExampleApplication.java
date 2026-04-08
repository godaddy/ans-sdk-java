package com.godaddy.ans.examples.springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Example Spring Boot application demonstrating ANS SDK auto-configuration.
 *
 * <p>This application uses {@code ans-sdk-spring-boot-starter} to automatically
 * configure ANS SDK beans from {@code application.yml} properties.</p>
 *
 * <h2>Running</h2>
 * <pre>
 * # Set credentials
 * export ANS_API_KEY=your-api-key
 * export ANS_API_SECRET=your-api-secret
 *
 * # Run the application
 * ./gradlew :ans-sdk-spring-boot-starter:examples:spring-boot-app:bootRun
 *
 * # Register an agent
 * curl -X POST http://localhost:8080/api/agents/register \
 *   -H "Content-Type: application/json" \
 *   -d '{"agentHost": "my-agent.example.com", "agentVersion": "1.0.0"}'
 *
 * # Resolve an agent
 * curl http://localhost:8080/api/agents/resolve?agentHost=my-agent.example.com
 * </pre>
 */
@SpringBootApplication
public class AnsExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(AnsExampleApplication.class, args);
    }
}
