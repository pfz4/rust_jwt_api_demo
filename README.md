# Rust JWT API Demo
This Project is a demo implementation for JWT Bearer Offline Verification using Rust Rocket. 
Keep in mind, that you need short Access Token lifespans when using Offline Verification, because the OpenID Server can't revoke the Access Keys.

The Server answers with "Hello, World!" when the JWT Token is not valid. When the Token is valid, the Server answers with a personalized message.


## Env Variables
|Name|Description|Example|
|---|---|---|
|`ISSUER`|Issuer Endpoint of the OpenID Connect Server|`https://example.com/auth/realms/demo`|
|`AUDIENCE`|Space separated list of valid audiences|`API-1 API-2`|