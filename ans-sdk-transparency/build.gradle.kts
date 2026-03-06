val jacksonVersion: String by project
val slf4jVersion: String by project
val junitVersion: String by project
val mockitoVersion: String by project
val assertjVersion: String by project
val wiremockVersion: String by project

dependencies {
    // Core module for exceptions and HTTP utilities
    api(project(":ans-sdk-core"))

    // Crypto module for certificate utilities (fingerprint, SAN extraction)
    api(project(":ans-sdk-crypto"))

    // Jackson for JSON serialization
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")

    // Logging
    implementation("org.slf4j:slf4j-api:$slf4jVersion")

    // dnsjava for _ra-badge TXT record lookups (JNDI doesn't support all TXT features)
    implementation("dnsjava:dnsjava:3.6.4")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.mockito:mockito-core:$mockitoVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")
    testImplementation("org.wiremock:wiremock:$wiremockVersion")
    testRuntimeOnly("org.slf4j:slf4j-simple:$slf4jVersion")
}