// Spring Boot Example - demonstrates ANS SDK auto-configuration

plugins {
    id("org.springframework.boot") version "4.0.6"
    id("io.spring.dependency-management") version "1.1.7"
}

dependencies {
    implementation(project(":ans-sdk-spring-boot-starter"))
    implementation("org.springframework.boot:spring-boot-starter-web")
}
