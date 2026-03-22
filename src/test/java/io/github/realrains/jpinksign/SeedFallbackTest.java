package io.github.realrains.jpinksign;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

class SeedFallbackTest {
    @Test
    void testSeedEncryptFallsBackToPure() {
        SeedCryptoBackend previous = SeedCbcCipher.setBackendForTests(new SeedCryptoBackend() {
            @Override
            public byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) throws PinkSignException {
                throw new PinkSignException("seed");
            }

            @Override
            public byte[] decrypt(byte[] key, byte[] ciphertext, byte[] iv) {
                return new byte[0];
            }
        });
        try {
            byte[] expected = PinkSignFunctions.seedCbc128EncryptPure(Fixtures.KEY, Fixtures.PLAINTEXT, Fixtures.IV);
            assertArrayEquals(expected, PinkSignFunctions.seedCbc128Encrypt(Fixtures.KEY, Fixtures.PLAINTEXT, Fixtures.IV));
        } finally {
            SeedCbcCipher.setBackendForTests(previous);
        }
    }

    @Test
    void testSeedDecryptFallsBackToPure() {
        SeedCryptoBackend previous = SeedCbcCipher.setBackendForTests(new SeedCryptoBackend() {
            @Override
            public byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) {
                return new byte[0];
            }

            @Override
            public byte[] decrypt(byte[] key, byte[] ciphertext, byte[] iv) throws PinkSignException {
                throw new PinkSignException("seed");
            }
        });
        try {
            byte[] ciphertext = PinkSignFunctions.seedCbc128EncryptPure(Fixtures.KEY, Fixtures.PLAINTEXT, Fixtures.IV);
            byte[] expected = PinkSignFunctions.seedCbc128DecryptPure(Fixtures.KEY, ciphertext, Fixtures.IV);
            assertArrayEquals(expected, PinkSignFunctions.seedCbc128Decrypt(Fixtures.KEY, ciphertext, Fixtures.IV));
        } finally {
            SeedCbcCipher.setBackendForTests(previous);
        }
    }
}
