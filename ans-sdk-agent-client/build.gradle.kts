val jacksonVersion: String by project
val bouncyCastleVersion: String by project
val slf4jVersion: String by project
val reactorVersion: String by project
val junitVersion: String by project
val mockitoVersion: String by project
val assertjVersion: String by project
val wiremockVersion: String by project

dependencies {
    // Core and crypto modules
    api(project(":ans-sdk-core"))
    api(project(":ans-sdk-crypto"))
    api(project(":ans-sdk-api"))
    api(project(":ans-sdk-transparency"))

    // Project Reactor for reactive streams
    api("io.projectreactor:reactor-core:$reactorVersion")

    // Jackson for JSON serialization
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")

    // Bouncy Castle for crypto operations (already in crypto module, but making explicit)
    implementation("org.bouncycastle:bcpkix-jdk18on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")

    // dnsjava for DANE/TLSA DNS lookups (JNDI doesn't support TLSA)
    implementation("dnsjava:dnsjava:3.6.0")

    // Logging
    implementation("org.slf4j:slf4j-api:$slf4jVersion")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.mockito:mockito-core:$mockitoVersion")
    testImplementation("org.mockito:mockito-junit-jupiter:$mockitoVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")
    testImplementation("org.wiremock:wiremock:$wiremockVersion")
    testImplementation("io.projectreactor:reactor-test:$reactorVersion")
    testRuntimeOnly("org.slf4j:slf4j-simple:$slf4jVersion")
}