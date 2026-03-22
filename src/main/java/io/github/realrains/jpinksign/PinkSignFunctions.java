package io.github.realrains.jpinksign;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public final class PinkSignFunctions {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PinkSignFunctions() {
    }

    public static byte[] seedCbc128Encrypt(byte[] key, byte[] plaintext) throws PinkSignException {
        return seedCbc128Encrypt(key, plaintext, PinkSignSupport.DEFAULT_SEED_IV);
    }

    public static byte[] seedCbc128Encrypt(byte[] key, byte[] plaintext, byte[] iv) throws PinkSignException {
        return SeedCbcCipher.encrypt(key, plaintext, iv);
    }

    public static byte[] seedCbc128Decrypt(byte[] key, byte[] ciphertext) throws PinkSignException {
        return seedCbc128Decrypt(key, ciphertext, PinkSignSupport.DEFAULT_SEED_IV);
    }

    public static byte[] seedCbc128Decrypt(byte[] key, byte[] ciphertext, byte[] iv) throws PinkSignException {
        return SeedCbcCipher.decrypt(key, ciphertext, iv);
    }

    public static byte[] seedCbc128EncryptProvider(byte[] key, byte[] plaintext, byte[] iv) throws PinkSignException {
        return SeedCbcCipher.encryptProvider(key, plaintext, iv);
    }

    public static byte[] seedCbc128DecryptProvider(byte[] key, byte[] ciphertext, byte[] iv) throws PinkSignException {
        return SeedCbcCipher.decryptProvider(key, ciphertext, iv);
    }

    public static byte[] seedCbc128EncryptPure(byte[] key, byte[] plaintext, byte[] iv) {
        return SeedCbcCipher.encryptPure(key, plaintext, iv);
    }

    public static byte[] seedCbc128DecryptPure(byte[] key, byte[] ciphertext, byte[] iv) {
        return SeedCbcCipher.decryptPure(key, ciphertext, iv);
    }

    public static byte[] seedGenerator(int size) {
        if (size < 0) {
            throw new IllegalArgumentException("Size must be non-negative.");
        }
        byte[] output = new byte[size];
        for (int index = 0; index < size; index++) {
            byte next;
            do {
                next = (byte) SECURE_RANDOM.nextInt(256);
            } while (next == 0);
            output[index] = next;
        }
        return output;
    }

    public static NpkiMaterial separateP12IntoNpki(byte[] p12Data, byte[] password) throws PinkSignException {
        return PinkSignSupport.separatePkcs12IntoNpki(p12Data, password);
    }

    public static String encryptDecryptedPrivateKey(String privateKeyBase64, byte[] password) throws PinkSignException {
        return encryptDecryptedPrivateKey(privateKeyBase64, password, null, 2048);
    }

    public static String encryptDecryptedPrivateKey(String privateKeyBase64, byte[] password, String saltBase64)
            throws PinkSignException {
        return encryptDecryptedPrivateKey(privateKeyBase64, password, saltBase64, 2048);
    }

    public static String encryptDecryptedPrivateKey(String privateKeyBase64, byte[] password, String saltBase64, int iterationCount)
            throws PinkSignException {
        return PinkSignSupport.encryptDecryptedPrivateKey(privateKeyBase64, password, saltBase64, iterationCount);
    }

    public static String injectRandInPlainPrivateKey(String privateKeyBase64, byte[] randNum) throws PinkSignException {
        return PinkSignSupport.injectRandInPlainPrivateKey(privateKeyBase64, randNum);
    }

    public static byte[] setKey(byte[] rawKey) {
        return SeedBlockCipher.setKey(rawKey);
    }

    public static byte[] processBlock(boolean encrypt, byte[] rawKey, byte[] input) {
        return SeedBlockCipher.processBlock(encrypt, rawKey, input);
    }

    static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
