# Resource Server

This module implements an OAuth2 Resource Server using Spring Security OAuth2. It provides protected resources that can only be accessed with valid tokens issued by the authorization server.

## Overview

The Resource Server is responsible for:
- Validating access tokens from clients
- Providing protected resources (APIs)
- Enforcing scope-based access control
- Integrating with the authorization server for token validation

## Features

- **OAuth2 Resource Server**: Implements the OAuth2 resource server specification
- **JWT Validation**: Validates JWT tokens issued by the authorization server
- **Scope-Based Security**: Restricts access to resources based on token scopes
- **REST API**: Provides RESTful APIs for accessing protected resources

## Configuration

### Application Properties

Key configurations in `application.properties`:

```properties
server.port=8090
spring.application.name=resource-server

# OAuth2 Resource Server Configuration
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9000
```

### Security Configuration

The `SecurityConfig` class configures:
- OAuth2 resource server with JWT validation
- Security for the "/products/**" endpoints requiring the "SCOPE_read" authority
- Integration with the authorization server for token validation

## Controllers

### ResourceController

The `ResourceController` class:
- Provides the "/products" endpoint that returns a list of products
- Is protected by OAuth2 security requiring valid tokens with the "read" scope

## Getting Started

### Prerequisites

- Java 21
- Authorization Server running on port 9000
- GraalVM 21 (for native image compilation)

### Running the Server (JVM Mode)

1. Ensure the Authorization Server is running:
   ```
   cd ../authorization-server
   ./gradlew bootRun
   ```

2. Run the Resource Server:
   ```
   ./gradlew bootRun
   ```

3. The server will be available at http://localhost:8090

### Native Image Support

This module supports native image compilation for improved startup time and reduced memory footprint. There are two approaches to build and run native images:

#### Approach 1: Using GraalVM Native Image (nativeCompile)

1. Build the native image:
   ```
   ./gradlew nativeCompile
   ```

2. Run the native executable:
   ```
   ./build/native/nativeCompile/resource-server
   ```

3. The server will be available at http://localhost:8090

#### Approach 2: Using Spring Boot's bootBuildImage Task (Recommended)

The `bootBuildImage` task uses Cloud Native Buildpacks to create optimized container images with native executables:

1. Build the container image:
   ```
   ./gradlew bootBuildImage
   ```

2. Run the container image using Docker:
   ```
   docker run -p 8090:8090 org.example.oauth2/resource-server:0.0.1-SNAPSHOT
   ```

3. The server will be available at http://localhost:8090

#### Using Docker with Native Image

##### Option 1: Using Dockerfile.native

1. Build and run using the provided Dockerfile.native:
   ```
   docker build -f Dockerfile.native -t resource-server-native .
   docker run -p 8090:8090 resource-server-native
   ```

##### Option 2: Using bootBuildImage (Recommended)

1. Build the image using bootBuildImage:
   ```
   ./gradlew bootBuildImage
   ```

2. Run the container:
   ```
   docker run -p 8090:8090 org.example.oauth2/resource-server:0.0.1-SNAPSHOT
   ```

The server will be available at http://localhost:8090

#### Native Image Benefits

- Faster startup time (typically under 100ms)
- Lower memory consumption
- Smaller deployment size
- No JVM required at runtime

## API Endpoints

- **GET /products**: Returns a list of products
  - Requires a valid access token with the "read" scope
  - Example response:
    ```json
    [
      "Product1",
      "Product2",
      "Product3",
      "Product4",
      "Product5"
    ]
    ```

## Token Validation

The resource server validates tokens by:
1. Verifying the token's signature using the authorization server's public key
2. Checking that the token was issued by the configured issuer (http://localhost:9000)
3. Ensuring the token is not expired
4. Verifying that the token contains the required scopes

## Integration with Other Modules

- **Authorization Server**: Issues and signs the tokens that this server validates
- **Client Server**: Accesses this server's protected resources using tokens from the authorization server

## Security Considerations

- The resource server only accepts valid JWT tokens issued by the authorization server
- Access to resources is restricted based on token scopes
- The server validates the token's signature, expiration, and issuer
- Communication with clients should be over HTTPS in production environments