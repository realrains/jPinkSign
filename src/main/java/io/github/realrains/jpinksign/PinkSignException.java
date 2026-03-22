package io.github.realrains.jpinksign;

public final class PinkSignException extends Exception {
    private final boolean retryWithPureFallback;

    public PinkSignException(String message) {
        this(message, null, false);
    }

    public PinkSignException(String message, Throwable cause) {
        this(message, cause, false);
    }

    private PinkSignException(String message, Throwable cause, boolean retryWithPureFallback) {
        super(message, cause);
        this.retryWithPureFallback = retryWithPureFallback;
    }

    static PinkSignException retryWithPureFallback(String message) {
        return new PinkSignException(message, null, true);
    }

    static PinkSignException retryWithPureFallback(String message, Throwable cause) {
        return new PinkSignException(message, cause, true);
    }

    boolean retryWithPureFallback() {
        return retryWithPureFallback;
    }
}
