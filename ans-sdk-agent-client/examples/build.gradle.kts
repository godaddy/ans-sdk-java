// Parent build file for ANS SDK examples
// Each subdirectory is a standalone example demonstrating SDK usage

subprojects {
    apply(plugin = "java")
    apply(plugin = "application")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(17))
        }
    }

    repositories {
        mavenLocal()
        mavenCentral()
    }

    val slf4jVersion: String by project

    dependencies {
        // All examples depend on the agent-client SDK
        implementation(project(":ans-sdk-agent-client"))

        // Logging
        implementation("org.slf4j:slf4j-api:$slf4jVersion")
        runtimeOnly("org.slf4j:slf4j-simple:$slf4jVersion")
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
    }
}