import java.net.URI

plugins {
    id("org.openapi.generator")
}

val jacksonVersion: String by project

// Authoritative source for the API spec
val apiSpecUrl = "https://developer.godaddy.com/swagger/swagger_ans.json"
val apiSpecFile = layout.buildDirectory.file("api-spec.json")

dependencies {
    // Jackson for JSON serialization
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.core:jackson-annotations:$jacksonVersion")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")

    // Jakarta annotations
    implementation("jakarta.annotation:jakarta.annotation-api:3.0.0")
}

// Task to download the API spec from the authoritative source
val downloadApiSpec by tasks.registering {
    val outputFile = apiSpecFile
    outputs.file(outputFile)
    doLast {
        val destFile = outputFile.get().asFile
        destFile.parentFile.mkdirs()
        URI.create(apiSpecUrl).toURL().openStream().use { input ->
            destFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        logger.lifecycle("Downloaded API spec from $apiSpecUrl")
    }
}

openApiGenerate {
    generatorName.set("java")
    inputSpec.set(apiSpecFile.get().asFile.absolutePath)
    outputDir.set(layout.buildDirectory.dir("generated").get().asFile.absolutePath)
    apiPackage.set("com.godaddy.ans.sdk.api.generated")
    modelPackage.set("com.godaddy.ans.sdk.model.generated")
    invokerPackage.set("com.godaddy.ans.sdk.client.generated")
    configOptions.set(mapOf(
        "library" to "native",
        "dateLibrary" to "java8",
        "useJakartaEe" to "true",
        "openApiNullable" to "false",
        "serializationLibrary" to "jackson",
        "hideGenerationTimestamp" to "true"
    ))
}

sourceSets {
    main {
        java {
            srcDir(layout.buildDirectory.dir("generated/src/main/java"))
        }
    }
}

tasks.openApiGenerate {
    dependsOn(downloadApiSpec)
}

tasks.compileJava {
    dependsOn(tasks.openApiGenerate)
}

// Disable checkstyle for generated code
tasks.named("checkstyleMain") {
    enabled = false
}