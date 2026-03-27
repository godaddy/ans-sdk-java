plugins {
    java
    `java-library`
    checkstyle
    id("org.openapi.generator") version "7.21.0" apply false
    id("com.vanniktech.maven.publish") version "0.36.0" apply false
}

allprojects {
    group = "com.godaddy.ans"
    version = "0.1.5" // x-release-please-version
}

// Modules to publish (excludes examples)
val publishableModules = setOf(
    "ans-sdk-api",
    "ans-sdk-core",
    "ans-sdk-crypto",
    "ans-sdk-registration",
    "ans-sdk-discovery",
    "ans-sdk-agent-client",
    "ans-sdk-transparency",
    "ans-sdk-spring-boot-starter"
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

    // Only enforce 90% coverage on publishable modules (not examples)
    if (publishableModules.contains(project.name)) {
        tasks.withType<JacocoCoverageVerification> {
            violationRules {
                rule {
                    limit {
                        minimum = "0.90".toBigDecimal()
                    }
                }
            }
        }
    }

    // Apply publishing only to publishable modules
    if (name in publishableModules) {
        apply(plugin = "com.vanniktech.maven.publish")

        configure<com.vanniktech.maven.publish.MavenPublishBaseExtension> {
            publishToMavenCentral(automaticRelease = true)
            signAllPublications()

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
}