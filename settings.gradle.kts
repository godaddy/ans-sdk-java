rootProject.name = "ans-java-sdk"

include("ans-sdk-api")
include("ans-sdk-core")
include("ans-sdk-crypto")
include("ans-sdk-registration")
include("ans-sdk-discovery")
include("ans-sdk-agent-client")
include("ans-sdk-transparency")
include("ans-sdk-spring-boot-starter")

// Examples - not published to Maven, but useful for users of the SDK to reference and run locally
include("ans-sdk-agent-client:examples:http-api")
include("ans-sdk-agent-client:examples:mcp-client")
include("ans-sdk-agent-client:examples:a2a-client")
include("ans-sdk-spring-boot-starter:examples:spring-boot-app")