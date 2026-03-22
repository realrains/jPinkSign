package io.github.realrains.jpinksign;

interface SeedCryptoBackend {
    byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) throws PinkSignException;

    byte[] decrypt(byte[] key, byte[] ciphertext, byte[] iv) throws PinkSignException;
}
