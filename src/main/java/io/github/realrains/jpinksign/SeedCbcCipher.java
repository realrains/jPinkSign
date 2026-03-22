package io.github.realrains.jpinksign;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

final class SeedCbcCipher {
    private static volatile SeedCryptoBackend backend = new BouncyCastleSeedCryptoBackend();

    private SeedCbcCipher() {
    }

    static byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) {
        validateKeyAndIv(key, iv);
        try {
            return encryptProvider(key, plaintext, iv);
        } catch (PinkSignException e) {
            return encryptPure(key, plaintext, iv);
        }
    }

    static byte[] decrypt(byte[] key, byte[] ciphertext, byte[] iv) {
        validateKeyAndIv(key, iv);
        try {
            return decryptProvider(key, ciphertext, iv);
        } catch (PinkSignException e) {
            return decryptPure(key, ciphertext, iv);
        }
    }

    static byte[] encryptProvider(byte[] key, byte[] plaintext, byte[] iv) throws PinkSignException {
        validateKeyAndIv(key, iv);
        return backend.encrypt(key, plaintext, iv);
    }

    static byte[] decryptProvider(byte[] key, byte[] ciphertext, byte[] iv) throws PinkSignException {
        validateKeyAndIv(key, iv);
        return backend.decrypt(key, ciphertext, iv);
    }

    static byte[] encryptPure(byte[] key, byte[] plaintext, byte[] iv) {
        validateKeyAndIv(key, iv);
        byte[] padded = pad(plaintext);
        byte[] vector = Arrays.copyOf(iv, iv.length);
        ByteArrayOutputStream output = new ByteArrayOutputStream(padded.length);
        for (int offset = 0; offset < padded.length; offset += SeedBlockCipher.BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(padded, offset, offset + SeedBlockCipher.BLOCK_SIZE);
            byte[] encrypted = SeedBlockCipher.processBlock(true, key, xor(block, vector));
            output.write(encrypted, 0, encrypted.length);
            vector = encrypted;
        }
        return output.toByteArray();
    }

    static byte[] decryptPure(byte[] key, byte[] ciphertext, byte[] iv) {
        validateKeyAndIv(key, iv);
        if (ciphertext == null || ciphertext.length % SeedBlockCipher.BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Ciphertext must be a multiple of 16 bytes.");
        }
        byte[] vector = Arrays.copyOf(iv, iv.length);
        ByteArrayOutputStream output = new ByteArrayOutputStream(ciphertext.length);
        for (int offset = 0; offset < ciphertext.length; offset += SeedBlockCipher.BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(ciphertext, offset, offset + SeedBlockCipher.BLOCK_SIZE);
            byte[] decrypted = SeedBlockCipher.processBlock(false, key, block);
            byte[] plain = xor(decrypted, vector);
            output.write(plain, 0, plain.length);
            vector = block;
        }
        return unpad(output.toByteArray());
    }

    static SeedCryptoBackend setBackendForTests(SeedCryptoBackend replacement) {
        SeedCryptoBackend previous = backend;
        backend = replacement;
        return previous;
    }

    private static void validateKeyAndIv(byte[] key, byte[] iv) {
        PinkSignSupport.requireLength(key, SeedBlockCipher.BLOCK_SIZE, "SEED key");
        PinkSignSupport.requireLength(iv, SeedBlockCipher.BLOCK_SIZE, "SEED IV");
    }

    private static byte[] xor(byte[] left, byte[] right) {
        byte[] output = new byte[left.length];
        for (int index = 0; index < left.length; index++) {
            output[index] = (byte) (left[index] ^ right[index]);
        }
        return output;
    }

    private static byte[] pad(byte[] input) {
        int padding = SeedBlockCipher.BLOCK_SIZE - (input.length % SeedBlockCipher.BLOCK_SIZE);
        if (padding == 0) {
            padding = SeedBlockCipher.BLOCK_SIZE;
        }
        byte[] output = Arrays.copyOf(input, input.length + padding);
        Arrays.fill(output, input.length, output.length, (byte) padding);
        return output;
    }

    private static byte[] unpad(byte[] input) {
        if (input.length == 0 || input.length % SeedBlockCipher.BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Invalid PKCS7 input.");
        }
        int padding = input[input.length - 1] & 0xff;
        if (padding == 0 || padding > SeedBlockCipher.BLOCK_SIZE || padding > input.length) {
            throw new IllegalArgumentException("Invalid PKCS7 padding.");
        }
        for (int index = input.length - padding; index < input.length; index++) {
            if ((input[index] & 0xff) != padding) {
                throw new IllegalArgumentException("Invalid PKCS7 padding.");
            }
        }
        return Arrays.copyOf(input, input.length - padding);
    }
}
