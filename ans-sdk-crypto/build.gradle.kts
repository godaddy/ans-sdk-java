val bouncyCastleVersion: String by project
val slf4jVersion: String by project
val junitVersion: String by project
val mockitoVersion: String by project
val assertjVersion: String by project

dependencies {
    // Core module
    api(project(":ans-sdk-core"))

    // Bouncy Castle for crypto operations
    implementation("org.bouncycastle:bcpkix-jdk18on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")

    // Logging
    implementation("org.slf4j:slf4j-api:$slf4jVersion")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.mockito:mockito-core:$mockitoVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")
    testRuntimeOnly("org.slf4j:slf4j-simple:$slf4jVersion")
}