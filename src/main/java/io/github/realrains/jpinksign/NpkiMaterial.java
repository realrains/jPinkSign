package io.github.realrains.jpinksign;

import java.util.Arrays;

public final class NpkiMaterial {
    private final byte[] publicKeyData;
    private final byte[] privateKeyData;

    public NpkiMaterial(byte[] publicKeyData, byte[] privateKeyData) {
        this.publicKeyData = Arrays.copyOf(publicKeyData, publicKeyData.length);
        this.privateKeyData = Arrays.copyOf(privateKeyData, privateKeyData.length);
    }

    public byte[] publicKeyData() {
        return Arrays.copyOf(publicKeyData, publicKeyData.length);
    }

    public byte[] privateKeyData() {
        return Arrays.copyOf(privateKeyData, privateKeyData.length);
    }
}
