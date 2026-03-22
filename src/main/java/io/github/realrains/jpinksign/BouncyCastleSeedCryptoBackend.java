package io.github.realrains.jpinksign;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class BouncyCastleSeedCryptoBackend implements SeedCryptoBackend {
    @Override
    public byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) throws PinkSignException {
        return run(Cipher.ENCRYPT_MODE, key, plaintext, iv);
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] ciphertext, byte[] iv) throws PinkSignException {
        return run(Cipher.DECRYPT_MODE, key, ciphertext, iv);
    }

    private byte[] run(int mode, byte[] key, byte[] input, byte[] iv) throws PinkSignException {
        try {
            PinkSignSupport.ensureBouncyCastleProvider();
            Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS7Padding", PinkSignSupport.BC_PROVIDER_NAME);
            cipher.init(mode, new SecretKeySpec(key, "SEED"), new IvParameterSpec(iv));
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw PinkSignException.retryWithPureFallback("SEED provider is unavailable.", e);
        } catch (GeneralSecurityException e) {
            throw new PinkSignException("SEED provider operation failed.", e);
        }
    }
}
