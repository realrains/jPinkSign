import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository

plugins {
    `java-library`
    `maven-publish`
}

group = "io.github.realrains"
version = "0.1.0"

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
    withJavadocJar()
}

dependencies {
    api("org.jspecify:jspecify:1.0.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(11)
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifactId = "jpinksign"
        }
    }

    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/realrains/jPinkSign")
            credentials {
                username = providers.gradleProperty("gpr.user")
                    .orElse(providers.environmentVariable("GITHUB_ACTOR"))
                    .orNull
                password = providers.gradleProperty("gpr.key")
                    .orElse(providers.environmentVariable("GITHUB_TOKEN"))
                    .orNull
            }
        }
    }
}

val requireReleaseVersion by tasks.registering {
    group = "publishing"
    description = "Fails GitHub Packages publishing when the project version is still a snapshot."

    doLast {
        check(!version.toString().endsWith("-SNAPSHOT")) {
            "GitHub Packages publishing requires a non-SNAPSHOT version. " +
                "Update version in build.gradle.kts before creating a release."
        }
    }
}

tasks.withType<PublishToMavenRepository>().configureEach {
    if (repository.name == "GitHubPackages") {
        dependsOn(requireReleaseVersion)
    }
}
