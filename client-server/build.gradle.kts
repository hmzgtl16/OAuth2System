import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    java
    id("org.springframework.boot") version "3.5.3"
    id("io.spring.dependency-management") version "1.1.7"
    //id("org.graalvm.buildtools.native") version "0.11.0"
}

group = "org.example.oauth2"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

/*
// Configure GraalVM Native Image options
graalvmNative {
	metadataRepository {
		enabled = true
	}
}

// Configure bootBuildImage task
tasks.named<BootBuildImage>("bootBuildImage") {
    imageName = "${project.group}/${project.name}:${project.version}"

    // Enable building native images with Cloud Native Buildpacks
    builder = "paketobuildpacks/builder-jammy-tiny"
    runImage = "paketobuildpacks/run-jammy-tiny"
    environment.put("BP_NATIVE_IMAGE", "true")
	environment.put("BP_NATIVE_IMAGE_BUILD_ARGUMENTS", "--verbose --no-fallback -H:+ReportExceptionStackTraces")
	environment.put("BP_JVM_VERSION", "21")
	environment.put("BP_JVM_CDS_ENABLED", "true")
}
*/
