# Publishing jPinkSign

This document is for maintainers publishing `jPinkSign` to GitHub Packages.

## Package target

Published coordinates:

```text
io.github.realrains:jpinksign:<version>
```

Registry URL:

```text
https://maven.pkg.github.com/realrains/jPinkSign
```

## Release rules

- Remote publishing is only allowed when `version` in `build.gradle.kts` does not end with `-SNAPSHOT`.
- GitHub Packages publishing uses `GITHUB_ACTOR` and `GITHUB_TOKEN` in CI.
- Local Gradle publishing credentials fall back to `gpr.user` and `gpr.key`.

## Release flow

1. Update `version` in `build.gradle.kts` to the release version.
2. Run `./gradlew build` locally.
3. Commit and push the version change to `main`.
4. Create a GitHub Release for that version, or run the `Publish` workflow manually with `workflow_dispatch`.
5. GitHub Actions runs `./gradlew requireReleaseVersion publish`.
6. Confirm the package appears in the repository's GitHub Packages page with the main JAR, sources JAR, and javadoc JAR.

## Local checks

Useful commands before creating the release:

```bash
./gradlew build
./gradlew publishToMavenLocal
./gradlew tasks --all
```

If `version` still ends with `-SNAPSHOT`, this command should fail:

```bash
./gradlew requireReleaseVersion
```

Expected failure message:

```text
GitHub Packages publishing requires a non-SNAPSHOT version. Update version in build.gradle.kts before creating a release.
```

## Workflow entrypoints

- CI workflow: `.github/workflows/ci.yml`
- Publish workflow: `.github/workflows/publish.yml`
