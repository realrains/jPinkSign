package io.github.realrains.jpinksign;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SeedFallbackTest {
    @Test
    void testSeedEncryptFallsBackToPure() throws Exception {
        SeedCryptoBackend previous = SeedCbcCipher.setBackendForTests(new SeedCryptoBackend() {
            @Override
            public byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) throws PinkSignException {
                throw PinkSignException.retryWithPureFallback("seed");
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
    void testSeedDecryptFallsBackToPure() throws Exception {
        SeedCryptoBackend previous = SeedCbcCipher.setBackendForTests(new SeedCryptoBackend() {
            @Override
            public byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) {
                return new byte[0];
            }

            @Override
            public byte[] decrypt(byte[] key, byte[] ciphertext, byte[] iv) throws PinkSignException {
                throw PinkSignException.retryWithPureFallback("seed");
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

    @Test
    void testSeedDecryptDoesNotFallbackOnProviderFailure() {
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
            assertThrows(PinkSignException.class, () -> PinkSignFunctions.seedCbc128Decrypt(Fixtures.KEY, ciphertext, Fixtures.IV));
        } finally {
            SeedCbcCipher.setBackendForTests(previous);
        }
    }

    @Test
    void testSeedDecryptWrapsPureFailureAsPinkSignException() {
        SeedCryptoBackend previous = SeedCbcCipher.setBackendForTests(new SeedCryptoBackend() {
            @Override
            public byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) {
                return new byte[0];
            }

            @Override
            public byte[] decrypt(byte[] key, byte[] ciphertext, byte[] iv) throws PinkSignException {
                throw PinkSignException.retryWithPureFallback("seed");
            }
        });
        try {
            assertThrows(PinkSignException.class, () -> PinkSignFunctions.seedCbc128Decrypt(Fixtures.KEY, new byte[16], Fixtures.IV));
        } finally {
            SeedCbcCipher.setBackendForTests(previous);
        }
    }
}
