plugins {
    java
    `java-library`
    checkstyle
    id("org.openapi.generator") version "7.20.0" apply false
}

allprojects {
    group = "com.godaddy.ans"
    version = "0.1.0"
}

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
}