package io.github.realrains.jpinksign;

import org.jspecify.annotations.Nullable;

public final class PinkSignException extends Exception {
    private final boolean retryWithPureFallback;

    public PinkSignException(String message) {
        this(message, null, false);
    }

    public PinkSignException(String message, Throwable cause) {
        this(message, cause, false);
    }

    private PinkSignException(String message, @Nullable Throwable cause, boolean retryWithPureFallback) {
        super(message, cause);
        this.retryWithPureFallback = retryWithPureFallback;
    }

    static PinkSignException retryWithPureFallback(String message) {
        return new PinkSignException(message, null, true);
    }

    static PinkSignException retryWithPureFallback(String message, @Nullable Throwable cause) {
        return new PinkSignException(message, cause, true);
    }

    boolean retryWithPureFallback() {
        return retryWithPureFallback;
    }
}
