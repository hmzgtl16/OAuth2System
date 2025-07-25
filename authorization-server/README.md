# Authorization Server

This module implements an OAuth2 Authorization Server using Spring Security OAuth2. It handles authentication and issues tokens for the OAuth2 system.

## Overview

The Authorization Server is responsible for:
- Authenticating users
- Issuing access tokens and refresh tokens
- Managing client registrations
- Supporting various OAuth2 grant types
- Providing OpenID Connect (OIDC) functionality

## Features

- **OAuth2 Authorization Server**: Implements the OAuth2 specification for issuing tokens
- **OpenID Connect Support**: Provides OIDC functionality for authentication
- **Multiple Grant Types**: Supports authorization_code, refresh_token, client_credentials, and device_code grant types
- **Redis Storage**: Uses Redis for storing tokens, authorizations, and client registrations
- **User Authentication**: Provides a login form for user authentication

## Configuration

### Application Properties

Key configurations in `application.properties`:

```properties
server.port=9000
spring.application.name=authorization-server
spring.data.redis.host=localhost
spring.data.redis.port=6379
spring.security.oauth2.authorizationserver.issuer=http://localhost:9000
```

### Security Configuration

The `SecurityConfig` class configures:
- OAuth2 authorization server endpoints with OIDC support
- Form-based login for user authentication
- In-memory user details service with a default user

### Registered Clients

The `RegisteredClients` class defines the OAuth2 clients that can request tokens:
- Client ID: products-client
- Grant Types: authorization_code, refresh_token, client_credentials, device_code
- Scopes: openid, profile, read, write
- Redirect URIs for the client application

## Redis Configuration

The server uses Redis for persistent storage of:
- OAuth2 authorizations
- Client registrations
- User consents

Redis connection is configured in `RedisConfig` class and the application properties.

## Model Classes

The module includes several model classes for different OAuth2 authorization types:
- `OAuth2GrantAuthorization`: Base class for all authorizations
- `OAuth2CodeGrantAuthorization`: For authorization code grants
- `OAuth2ClientCredentialsGrantAuthorization`: For client credentials grants
- `OAuth2DeviceCodeGrantAuthorization`: For device code grants
- `OAuth2TokenExchangeGrantAuthorization`: For token exchange grants
- `OidcCodeGrantAuthorization`: For OpenID Connect code grants

## Repositories and Services

- `OAuth2AuthorizationGrantAuthorizationRepository`: Manages authorization storage
- `OAuth2RegisteredClientRepository`: Manages client registration storage
- `OAuth2UserConsentRepository`: Manages user consent storage
- `RedisOAuth2AuthorizationService`: Implements OAuth2 authorization service using Redis
- `RedisOAuth2AuthorizationConsentService`: Implements OAuth2 authorization consent service using Redis
- `RedisRegisteredClientRepository`: Implements registered client repository using Redis

## Getting Started

### Prerequisites

- Java 21
- Redis (can be run using Docker)
- GraalVM 21 (for native image compilation)

### Running the Server (JVM Mode)

1. Start Redis:
   ```
   docker-compose up -d redis
   ```

2. Run the application:
   ```
   ./gradlew bootRun
   ```

3. The server will be available at http://localhost:9000

### Native Image Support

This module supports native image compilation for improved startup time and reduced memory footprint. There are two approaches to build and run native images:

#### Approach 1: Using GraalVM Native Image (nativeCompile)

1. Build the native image:
   ```
   ./gradlew nativeCompile
   ```

2. Run the native executable:
   ```
   ./build/native/nativeCompile/authorization-server
   ```

3. The server will be available at http://localhost:9000

#### Approach 2: Using Spring Boot's bootBuildImage Task (Recommended)

The `bootBuildImage` task uses Cloud Native Buildpacks to create optimized container images with native executables:

1. Build the container image:
   ```
   ./gradlew bootBuildImage
   ```

2. Run the container image using Docker:
   ```
   docker run -p 9000:9000 org.example.oauth2/authorization-server:0.0.1-SNAPSHOT
   ```

3. The server will be available at http://localhost:9000

#### Using Docker with Native Image

##### Option 1: Using Dockerfile.native

1. Build and run using the provided Dockerfile.native:
   ```
   docker build -f Dockerfile.native -t authorization-server-native .
   docker run -p 9000:9000 authorization-server-native
   ```

##### Option 2: Using bootBuildImage (Recommended)

1. Build the image using bootBuildImage:
   ```
   ./gradlew bootBuildImage
   ```

2. Run the container:
   ```
   docker run -p 9000:9000 org.example.oauth2/authorization-server:0.0.1-SNAPSHOT
   ```

The server will be available at http://localhost:9000

#### Native Image Benefits

- Faster startup time (typically under 100ms)
- Lower memory consumption
- Smaller deployment size
- No JVM required at runtime

## Endpoints

- **Authorization Endpoint**: `/oauth2/authorize`
- **Token Endpoint**: `/oauth2/token`
- **JWK Set Endpoint**: `/oauth2/jwks`
- **Token Introspection Endpoint**: `/oauth2/introspect`
- **Token Revocation Endpoint**: `/oauth2/revoke`
- **OIDC User Info Endpoint**: `/userinfo`
- **OIDC Client Registration Endpoint**: `/connect/register`

## Default User

The server is configured with a default user:
- Username: `user`
- Password: `password`

## Integration with Other Modules

- **Client Server**: Authenticates users through this authorization server
- **Resource Server**: Validates tokens issued by this authorization server