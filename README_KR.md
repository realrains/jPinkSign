<p align="right">
  <a href="./README.md">English</a> | <a href="./README_KR.md">한국어</a>
</p>

# jPinkSign

`jPinkSign`은 한국 NPKI 인증서와 관련 암호화 유틸리티를 다루기 위한 Java 라이브러리입니다.

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

### 간단한 예제

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

        System.out.println("CN: " + pinkSign.cn());
        System.out.println("Issuer: " + pinkSign.issuer());
        System.out.println("Verified: " + pinkSign.verify(signature, message));
    }
}
```

## 메인테이너 배포

메인테이너용 패키지 릴리스 절차는 [PUBLISH.md](PUBLISH.md)에 정리되어 있습니다.
