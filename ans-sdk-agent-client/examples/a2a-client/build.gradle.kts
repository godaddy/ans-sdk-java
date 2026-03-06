// A2A Client Example - demonstrates ANS verification with A2A SDK

application {
    mainClass.set("com.godaddy.ans.examples.a2a.A2aClientExample")
}

dependencies {
    // A2A SDK from Maven Central
    implementation("io.github.a2asdk:a2a-java-sdk-client:1.0.0.Alpha3")
    implementation("io.github.a2asdk:a2a-java-sdk-client-transport-jsonrpc:1.0.0.Alpha3")
    implementation("io.github.a2asdk:a2a-java-sdk-http-client:1.0.0.Alpha3")
    implementation("io.github.a2asdk:a2a-java-sdk-spec:1.0.0.Alpha3")
}