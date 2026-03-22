<p align="right">
  <a href="./README.md">English</a> | <a href="./README_KR.md">한국어</a>
</p>

# jPinkSign

`jPinkSign`은 한국 NPKI 인증서와 관련 암호화 유틸리티를 다루기 위한 Java 라이브러리입니다.

## 요구 사항

- JDK 11 이상

이 프로젝트는 Java 11 소스 및 타깃 호환성으로 빌드됩니다.

## GitHub Packages

배포 위치:

```text
io.github.realrains:jpinksign:<version>
```

레지스트리 URL:

```text
https://maven.pkg.github.com/realrains/jPinkSign
```

### 패키지 사용하기

GitHub Packages 는 인증이 필요합니다. 로컬 Gradle 환경에서는 `~/.gradle/gradle.properties`에 인증 정보를 추가하세요:

```properties
gpr.user=YOUR_GITHUB_USERNAME
gpr.key=YOUR_GITHUB_TOKEN
```

그다음 GitHub Packages 저장소와 의존성을 추가하세요:

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

토큰에는 패키지 읽기 권한이 필요합니다. GitHub Actions에서 이 패키지를 사용하는 경우, 같은 저장소 컨텍스트에서는 일반적으로 `GITHUB_TOKEN`을 사용할 수 있습니다.

### 사용 예제

Java API는 인증서 파일 경로를 명시적으로 지정하는 방식을 지원합니다. Python 패키지와 달리, CN 기준으로 로컬 인증서를 자동 탐색하는 기능은 현재 제공하지 않습니다.

#### `signCert.der`와 `signPri.key` 불러오기

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

#### PFX / PKCS#12 인증서 불러오기

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

## 메인테이너 배포

메인테이너용 패키지 릴리스 절차는 [PUBLISH.md](PUBLISH.md)에 정리되어 있습니다.
