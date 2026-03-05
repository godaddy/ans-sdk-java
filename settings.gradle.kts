rootProject.name = "ans-java-sdk"

include("ans-sdk-api")
include("ans-sdk-core")
include("ans-sdk-crypto")
include("ans-sdk-registration")
include("ans-sdk-discovery")
include("ans-sdk-agent-client")
include("ans-sdk-transparency")

// Examples (under ans-sdk-agent-client)
include("ans-sdk-agent-client:examples:http-api")
include("ans-sdk-agent-client:examples:mcp-client")
include("ans-sdk-agent-client:examples:a2a-client")