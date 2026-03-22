package io.github.realrains.jpinksign;

import java.util.Arrays;

public final class KeyIv {
    private final byte[] key;
    private final byte[] iv;

    public KeyIv(byte[] key, byte[] iv) {
        this.key = Arrays.copyOf(key, key.length);
        this.iv = Arrays.copyOf(iv, iv.length);
    }

    public byte[] key() {
        return Arrays.copyOf(key, key.length);
    }

    public byte[] iv() {
        return Arrays.copyOf(iv, iv.length);
    }
}
