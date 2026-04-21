// Spring Boot MCP Server Example - demonstrates ANS-verifiable MCP server with:
// - Automatic SCITT artifact refresh (receipts and status tokens)
// - Client request verification with mTLS
// - Health indicators for SCITT artifact status

plugins {
    application
}

val springBootVersion = "4.0.5"
val bouncyCastleVersion: String by project

application {
    mainClass.set("com.godaddy.ans.examples.mcp.spring.McpServerSpringApplication")
}

configurations.all {
    // Exclude slf4j-simple to avoid conflict with Logback in tests
    exclude(group = "org.slf4j", module = "slf4j-simple")
}

dependencies {
    // Spring Boot BOM for version management
    implementation(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))

    // Spring Boot
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor:$springBootVersion")

    // MCP SDK (servlet transport)
    implementation("io.modelcontextprotocol.sdk:mcp:1.1.1")

    // ANS SDK - agent client includes transparency module transitively
    implementation(project(":ans-sdk-agent-client"))

    // Bouncy Castle for PEM certificate loading
    implementation("org.bouncycastle:bcpkix-jdk18on:$bouncyCastleVersion")

}

tasks.withType<Jar> {
    manifest {
        attributes(
            "Main-Class" to "com.godaddy.ans.examples.mcp.spring.McpServerSpringApplication"
        )
    }
}
