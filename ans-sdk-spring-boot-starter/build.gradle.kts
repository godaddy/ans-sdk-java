val junitVersion: String by project
val assertjVersion: String by project

val springBootVersion = "4.0.6"

dependencies {
    // ANS SDK modules
    api(project(":ans-sdk-core"))
    api(project(":ans-sdk-registration"))
    api(project(":ans-sdk-discovery"))

    // Spring Boot auto-configuration
    implementation("org.springframework.boot:spring-boot-autoconfigure:$springBootVersion")

    // Optional annotation processor for configuration metadata
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor:$springBootVersion")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")
    testImplementation("org.springframework.boot:spring-boot-starter-test:$springBootVersion")
}
