# Client Server

This module implements an OAuth2 Client application using Spring Security OAuth2. It authenticates users through the authorization server and accesses protected resources from the resource server.

## Overview

The Client Server is responsible for:
- Redirecting users to the authorization server for authentication
- Obtaining access tokens from the authorization server
- Using tokens to access protected resources from the resource server
- Providing a user interface for the application

## Features

- **OAuth2 Client**: Implements the OAuth2 client specification for authentication
- **OpenID Connect Support**: Uses OIDC for user authentication
- **Multiple Client Registrations**: Configured with both OIDC and authorization code client registrations
- **WebClient Integration**: Uses WebClient with OAuth2 support to access protected resources
- **Automatic Token Management**: Handles token acquisition, renewal, and usage automatically

## Configuration

### Application Properties

Key configurations in `application.properties`:

```properties
server.port=8080
spring.application.name=client-server

# OAuth2 Client Configuration
spring.security.oauth2.client.registration.products-client-oidc.provider=spring
spring.security.oauth2.client.registration.products-client-oidc.client-id=products-client
spring.security.oauth2.client.registration.products-client-oidc.client-secret=secret
spring.security.oauth2.client.registration.products-client-oidc.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.products-client-oidc.redirect-uri=http://127.0.0.1:8080/login/oauth2/code/{registrationId}
spring.security.oauth2.client.registration.products-client-oidc.scope=openid,profile,read,write
spring.security.oauth2.client.registration.products-client-oidc.client-name=products-client-oidc

spring.security.oauth2.client.provider.spring.issuer-uri=http://localhost:9000
```

### Security Configuration

The `SecurityConfig` class configures:
- OAuth2 login with the authorization server
- Security for all endpoints requiring authentication
- OAuth2 client support for accessing protected resources

### WebClient Configuration

The `WebClientConfig` class configures:
- A WebClient bean with OAuth2 support
- Integration with Spring Security's OAuth2 client support
- Automatic token inclusion in requests to the resource server

## Controllers

### HomeController

The `HomeController` class:
- Provides the main entry point for the application
- Uses WebClient to access the products API from the resource server
- Automatically includes OAuth2 tokens in requests to the resource server

## Getting Started

### Prerequisites

- Java 21
- Authorization Server running on port 9000
- Resource Server running on port 8090
- GraalVM 21 (for native image compilation)

### Running the Server (JVM Mode)

1. Ensure the Authorization Server is running:
   ```
   cd ../authorization-server
   ./gradlew bootRun
   ```

2. Ensure the Resource Server is running:
   ```
   cd ../resource-server
   ./gradlew bootRun
   ```

3. Run the Client Server:
   ```
   ./gradlew bootRun
   ```

4. Access the application at http://localhost:8080

## OAuth2 Flow

1. When a user accesses the application, they are redirected to the authorization server for authentication
2. After successful authentication, the authorization server redirects back to the client with an authorization code
3. The client exchanges the authorization code for access and refresh tokens
4. The client uses the access token to make requests to the resource server
5. When the access token expires, the client automatically uses the refresh token to obtain a new access token

## Integration with Other Modules

- **Authorization Server**: Authenticates users and issues tokens to this client
- **Resource Server**: Provides protected resources that this client accesses with tokens