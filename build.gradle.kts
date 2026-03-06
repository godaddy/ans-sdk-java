plugins {
    java
    `java-library`
    checkstyle
    id("org.openapi.generator") version "7.20.0" apply false
}

allprojects {
    group = "com.godaddy.ans"
    version = "0.1.0" // x-release-please-version
}

// Modules to publish (excludes examples)
val publishableModules = setOf(
    "ans-sdk-api",
    "ans-sdk-core",
    "ans-sdk-crypto",
    "ans-sdk-registration",
    "ans-sdk-discovery",
    "ans-sdk-agent-client",
    "ans-sdk-transparency"
)

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "checkstyle")
    apply(plugin = "jacoco")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(17))
        }
    }

    repositories {
        mavenCentral()
    }

    dependencies {
        // Required for Gradle 9.x JUnit Platform support
        testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    }

    checkstyle {
        toolVersion = "10.12.5"
        configFile = rootProject.file("config/checkstyle/checkstyle.xml")
        maxWarnings = 0
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
    }

    tasks.withType<Test> {
        finalizedBy(tasks.withType<JacocoReport>())
    }

    tasks.withType<JacocoReport> {
        dependsOn(tasks.withType<Test>())
        reports {
            xml.required.set(true)
            html.required.set(true)
        }
    }

    tasks.withType<JacocoCoverageVerification> {
        violationRules {
            rule {
                limit {
                    minimum = "0.90".toBigDecimal()
                }
            }
        }
    }

    // Apply publishing only to publishable modules
    if (name in publishableModules) {
        apply(plugin = "maven-publish")
        apply(plugin = "signing")

        java {
            withSourcesJar()
            withJavadocJar()
        }

        configure<PublishingExtension> {
            publications {
                create<MavenPublication>("mavenJava") {
                    from(components["java"])

                    pom {
                        name.set(project.name)
                        description.set("ANS SDK - ${project.name}")
                        url.set("https://github.com/godaddy/ans-sdk-java")

                        licenses {
                            license {
                                name.set("MIT License")
                                url.set("https://opensource.org/licenses/MIT")
                            }
                        }

                        developers {
                            developer {
                                id.set("godaddy")
                                name.set("GoDaddy")
                                email.set("oswg@godaddy.com")
                            }
                        }

                        scm {
                            connection.set("scm:git:git://github.com/godaddy/ans-sdk-java.git")
                            developerConnection.set("scm:git:ssh://github.com/godaddy/ans-sdk-java.git")
                            url.set("https://github.com/godaddy/ans-sdk-java")
                        }
                    }
                }
            }

            repositories {
                // Maven Central via Sonatype Central Portal
                maven {
                    name = "mavenCentral"
                    url = uri("https://central.sonatype.com/api/v1/publisher/upload")

                    credentials {
                        username = System.getenv("MAVEN_CENTRAL_USERNAME")
                            ?: project.findProperty("mavenCentralUsername") as String? ?: ""
                        password = System.getenv("MAVEN_CENTRAL_PASSWORD")
                            ?: project.findProperty("mavenCentralPassword") as String? ?: ""
                    }
                }
            }
        }

        configure<SigningExtension> {
            // Only sign when publishing to Maven Central (skip for local testing)
            setRequired({
                gradle.taskGraph.hasTask("publishAllPublicationsToMavenCentralRepository")
            })

            // Use GPG command (key imported by actions/setup-java)
            useGpgCmd()

            sign(the<PublishingExtension>().publications["mavenJava"])
        }
    }
}