package io.github.realrains.jpinksign;

import java.time.Instant;
import java.util.Objects;

public final class ValidityPeriod {
    private final Instant notBefore;
    private final Instant notAfter;

    public ValidityPeriod(Instant notBefore, Instant notAfter) {
        this.notBefore = Objects.requireNonNull(notBefore, "notBefore");
        this.notAfter = Objects.requireNonNull(notAfter, "notAfter");
    }

    public Instant notBefore() {
        return notBefore;
    }

    public Instant notAfter() {
        return notAfter;
    }
}
