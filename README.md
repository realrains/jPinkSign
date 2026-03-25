<p align="right">
  <a href="./README.md">English</a> | <a href="./README_KR.md">한국어</a>
</p>

# jPinkSign

`jPinkSign` is a Java library for working with Korean NPKI certificates and related crypto utilities.

## Requirements

- JDK 11 or newer

This project is built with Java 11 source and target compatibility.

The `io.github.realrains.jpinksign` package is `@NullMarked`, so types are non-nullable by default and only explicitly nullable APIs are marked.

## GitHub Packages

Published coordinates:

```text
io.github.realrains:jpinksign:<version>
```

Registry URL:

```text
https://maven.pkg.github.com/realrains/jPinkSign
```

### Consuming the package

GitHub Packages requires authentication. For local Gradle usage, add credentials to `~/.gradle/gradle.properties`:

```properties
gpr.user=YOUR_GITHUB_USERNAME
gpr.key=YOUR_GITHUB_TOKEN
```

Then add the GitHub Packages repository and dependency:

```kotlin
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/realrains/jPinkSign")
        credentials {
            username = providers.gradleProperty("gpr.user").orNull
            password = providers.gradleProperty("gpr.key").orNull
        }
    }
    mavenCentral()
}

dependencies {
    implementation("io.github.realrains:jpinksign:<version>")
}
```

Your token needs package read access. If you consume this package from GitHub Actions, you can usually use `GITHUB_TOKEN` for packages in the same repository context.

### Usage examples

The Java API supports explicit certificate file loading. Unlike the Python package, it does not currently provide automatic local certificate discovery by CN.

#### Load `signCert.der` and `signPri.key`

```java
import io.github.realrains.jpinksign.PinkSign;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class Example {
    public static void main(String[] args) throws Exception {
        PinkSign pinkSign = new PinkSign(
            Path.of("signCert.der"),
            Path.of("signPri.key"),
            "password".getBytes(StandardCharsets.UTF_8)
        );

        byte[] message = "hello jPinkSign".getBytes(StandardCharsets.UTF_8);
        byte[] signature = pinkSign.sign(message);
        byte[] pkcs7SignedMessage = pinkSign.pkcs7SignedMessage(message);

        System.out.println("CN: " + pinkSign.cn());
        System.out.println("Issuer: " + pinkSign.issuer());
        System.out.println("Verified: " + pinkSign.verify(signature, message));
        System.out.println("PKCS#7 bytes: " + pkcs7SignedMessage.length);
    }
}
```

#### Load a PFX / PKCS#12 certificate

```java
import io.github.realrains.jpinksign.PinkSign;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class Example {
    public static void main(String[] args) throws Exception {
        PinkSign pinkSign = PinkSign.fromPkcs12(
            Path.of("signCert.p12"),
            "password".getBytes(StandardCharsets.UTF_8)
        );

        byte[] message = "hello jPinkSign".getBytes(StandardCharsets.UTF_8);
        byte[] signature = pinkSign.sign(message);
        byte[] pkcs7SignedMessage = pinkSign.pkcs7SignedMessage(message);

        System.out.println("CN: " + pinkSign.cn());
        System.out.println("Issuer: " + pinkSign.issuer());
        System.out.println("Verified: " + pinkSign.verify(signature, message));
        System.out.println("PKCS#7 bytes: " + pkcs7SignedMessage.length);
    }
}
```

## Maintainer publishing

Package release instructions for maintainers are documented in [PUBLISH.md](PUBLISH.md).
