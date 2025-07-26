# OAuth2 System

A complete OAuth2 implementation with Spring Boot, demonstrating the OAuth2 authorization flow with separate authorization server, client application, and resource server.

## Project Overview

This project consists of three main modules:

1. **Authorization Server** - An OAuth2 authorization server that issues tokens and handles authentication
2. **Client Server** - A web application that authenticates users via the authorization server
3. **Resource Server** - A service that provides protected resources accessible with valid tokens

## Architecture

The system demonstrates a complete OAuth2 flow:

1. The client application redirects users to the authorization server for authentication
2. After successful authentication, the authorization server issues tokens to the client
3. The client uses these tokens to access protected resources on the resource server

## Modules

### Authorization Server

The authorization server handles authentication and issues tokens. It runs on port 9000 and uses Redis for storage.

Key features:
- OAuth2 Authorization Server with OIDC support
- Support for various grant types (authorization_code, refresh_token, client_credentials, device_code)
- Redis-based token and client storage

See [Authorization Server README](./authorization-server/README.md) for more details.

### Client Server

The client server is a web application that authenticates users through the authorization server. It runs on port 8080.

Key features:
- OAuth2 client with OIDC support
- Integration with the authorization server for authentication
- Access to protected resources on the resource server

See [Client Server README](./client-server/README.md) for more details.

### Resource Server

The resource server provides protected resources that can only be accessed with valid tokens. It runs on port 8090.

Key features:
- OAuth2 resource server with JWT validation
- Protected API endpoints requiring specific scopes
- Integration with the authorization server for token validation

See [Resource Server README](./resource-server/README.md) for more details.

## Getting Started

### Prerequisites

- Java 21
- Docker (for Redis)
- GraalVM 21 (for native image compilation)

### Running the Application (JVM Mode)

1. Start Redis:
   ```
   docker-compose up -d auth-store
   ```

2. Start the Authorization Server:
   ```
   cd authorization-server
   ./gradlew bootRun
   ```

3. Start the Resource Server:
   ```
   cd resource-server
   ./gradlew bootRun
   ```

4. Start the Client Server:
   ```
   cd client-server
   ./gradlew bootRun
   ```

5. Access the application at http://localhost:8080

### Running with Native Images

There are two approaches to build and run native images for this project:

#### Approach 1: Using GraalVM Native Image (nativeCompile)

1. Build the Authorization Server native image:
   ```
   cd authorization-server
   ./gradlew nativeCompile
   ```

2. Build the Resource Server native image:
   ```
   cd resource-server
   ./gradlew nativeCompile
   ```

3. Build the Client Server native image:
   ```
   cd client-server
   ./gradlew nativeCompile
   ```

4. Run the native executables:
   ```
   ./authorization-server/build/native/nativeCompile/authorization-server
   ./resource-server/build/native/nativeCompile/resource-server
   ./client-server/build/native/nativeCompile/client-server
   ```

#### Approach 2: Using Spring Boot's bootBuildImage Task (Recommended)

The `bootBuildImage` task uses Cloud Native Buildpacks to create optimized container images with native executables:

1. Build the Authorization Server container image:
   ```
   cd authorization-server
   ./gradlew bootBuildImage
   ```

2. Build the Resource Server container image:
   ```
   cd resource-server
   ./gradlew bootBuildImage
   ```

3. Build the Client Server container image:
   ```
   cd client-server
   ./gradlew bootBuildImage
   ```

4. Run the container images using Docker:
   ```
   docker run -p 9000:9000 org.example.oauth2/authorization-server:0.0.1-SNAPSHOT
   docker run -p 8090:8090 org.example.oauth2/resource-server:0.0.1-SNAPSHOT
   docker run -p 8080:8080 org.example.oauth2/client-server:0.0.1-SNAPSHOT
   ```

#### Using Docker Compose with Native Images

Run the entire system with native images using Docker Compose:

```
# First build the images with bootBuildImage
cd authorization-server && ./gradlew bootBuildImage && cd ..
cd resource-server && ./gradlew bootBuildImage && cd ..
cd client-server && ./gradlew bootBuildImage && cd ..

# Then run Docker Compose
docker-compose up
```

This will use the native container images built with bootBuildImage for all three modules and start the entire system. The build process may take some time on the first run.

Access the application at http://localhost:8080

## Flow Demonstration

1. Navigate to http://localhost:8080
2. You will be redirected to the authorization server for login
3. Log in with username `user` and password `password`
4. After successful authentication, you will be redirected back to the client application
5. The client application will display products retrieved from the resource server

## License

This project is open source and available under the [MIT License](LICENSE).