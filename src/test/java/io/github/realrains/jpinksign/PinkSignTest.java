package io.github.realrains.jpinksign;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PinkSignTest {
    private PinkSign pinkSign;

    @BeforeEach
    void setUp() throws Exception {
        pinkSign = new PinkSign(Fixtures.CERT_PUBKEY_DER, Fixtures.CERT_PRIKEY_DER, Fixtures.CERT_PASSWORD);
    }

    @Test
    void testLoadPublicKey() throws Exception {
        PinkSign cert = new PinkSign();
        cert.loadPublicKey(Fixtures.CERT_PUBKEY_DER);
        assertEquals(Fixtures.N, cert.publicKey().getModulus());
        assertEquals(java.math.BigInteger.valueOf(65537L), cert.publicKey().getPublicExponent());
    }

    @Test
    void testLoadPrivateKey() throws Exception {
        pinkSign.loadPrivateKey();
        assertEquals(Fixtures.P, pinkSign.privateKey().getPrimeP());
        assertEquals(Fixtures.Q, pinkSign.privateKey().getPrimeQ());
        assertEquals(Fixtures.D, pinkSign.privateKey().getPrivateExponent());
        assertEquals(Fixtures.DMP1, pinkSign.privateKey().getPrimeExponentP());
        assertEquals(Fixtures.DMQ1, pinkSign.privateKey().getPrimeExponentQ());
        assertEquals(Fixtures.IQMP, pinkSign.privateKey().getCrtCoefficient());
        assertEquals(Fixtures.N, pinkSign.privateKey().getModulus());
        assertEquals(java.math.BigInteger.valueOf(65537L), pinkSign.privateKey().getPublicExponent());
    }

    @Test
    void testLoadPkcs12() throws Exception {
        PinkSign cert = PinkSign.fromPkcs12(Fixtures.CERT_P12_DATA, Fixtures.CERT_PASSWORD);
        assertEquals(Fixtures.N, cert.publicKey().getModulus());
        assertEquals(Fixtures.P, cert.privateKey().getPrimeP());
        assertEquals(Fixtures.Q, cert.privateKey().getPrimeQ());
        assertEquals(Fixtures.D, cert.privateKey().getPrivateExponent());
        assertEquals(Fixtures.DMP1, cert.privateKey().getPrimeExponentP());
        assertEquals(Fixtures.DMQ1, cert.privateKey().getPrimeExponentQ());
        assertEquals(Fixtures.IQMP, cert.privateKey().getCrtCoefficient());
    }

    @Test
    void testLoadPkcs12File() throws Exception {
        Path tempFile = Files.createTempFile("jpinksign-", ".p12");
        Files.write(tempFile, Fixtures.CERT_P12_DATA);
        try {
            PinkSign cert = PinkSign.fromPkcs12(tempFile, Fixtures.CERT_PASSWORD);
            byte[] signed = cert.sign(Fixtures.ascii("1"));
            assertTrue(cert.verify(signed, Fixtures.ascii("1")));
            assertEquals(Fixtures.N, cert.publicKey().getModulus());
            assertEquals(Fixtures.P, cert.privateKey().getPrimeP());
            assertEquals(Fixtures.Q, cert.privateKey().getPrimeQ());
            assertEquals(Fixtures.D, cert.privateKey().getPrivateExponent());
            assertEquals(Fixtures.DMP1, cert.privateKey().getPrimeExponentP());
            assertEquals(Fixtures.DMQ1, cert.privateKey().getPrimeExponentQ());
            assertEquals(Fixtures.IQMP, cert.privateKey().getCrtCoefficient());
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @Test
    void testCn() throws Exception {
        assertEquals(Fixtures.CN, pinkSign.cn());
    }

    @Test
    void testIssuer() throws Exception {
        assertEquals(Fixtures.ISSUER, pinkSign.issuer());
    }

    @Test
    void testCertClass() throws Exception {
        assertEquals(Fixtures.CERT_CLASS, pinkSign.certClass());
    }

    @Test
    void testCertTypeOid() throws Exception {
        assertEquals(Fixtures.TYPE_OID, pinkSign.certTypeOid());
    }

    @Test
    void testValidDate() {
        ValidityPeriod period = pinkSign.validDate();
        assertEquals(Fixtures.NOT_VALID_BEFORE, period.notBefore());
        assertEquals(Fixtures.NOT_VALID_AFTER, period.notAfter());
    }

    @Test
    void testSerialNumber() {
        assertEquals(Fixtures.SERIALNUM, pinkSign.serialNumber());
    }

    @Test
    void testSign() throws Exception {
        pinkSign.loadPrivateKey();
        assertArrayEquals(Fixtures.SIGN, pinkSign.sign(Fixtures.TEST_MSG));
    }

    @Test
    void testVerify() throws Exception {
        pinkSign.loadPrivateKey();
        assertTrue(pinkSign.verify(Fixtures.SIGN, Fixtures.TEST_MSG));
        assertFalse(pinkSign.verify(Fixtures.TEST_MSG, Fixtures.TEST_MSG));
    }

    @Test
    void testEncryptDecrypt() throws Exception {
        pinkSign.loadPrivateKey();
        assertArrayEquals(Fixtures.TEST_MSG, pinkSign.decrypt(pinkSign.encrypt(Fixtures.TEST_MSG)));
    }

    @Test
    void testGetPrivateKeyDecryptionKeyForSeedCbcWithSha1() throws Exception {
        ASN1Sequence der = PinkSignSupport.parseSequence(Fixtures.CERT_PRIKEY_DER);
        KeyIv keyIv = pinkSign.getPrivateKeyDecryptionKeyForSeedCbcWithSha1(der);
        assertArrayEquals(Fixtures.decodeHex("6240e2686a6abbc48c922ccba906bb91"), keyIv.key());
        assertArrayEquals(Fixtures.decodeHex("4471a1fd154167f22848770d578a5b73"), keyIv.iv());
    }

    @Test
    void testGetPrivateKeyDecryptionKeyForSeedCbc() throws Exception {
        ASN1Sequence der = PinkSignSupport.parseSequence(Fixtures.CERT_PRIKEY_DER);
        KeyIv keyIv = pinkSign.getPrivateKeyDecryptionKeyForSeedCbc(der);
        assertArrayEquals(Fixtures.decodeHex("6240e2686a6abbc48c922ccba906bb91"), keyIv.key());
        assertArrayEquals(Fixtures.ascii("0123456789012345"), keyIv.iv());
    }

    @Test
    void testGetPrivateKeyDecryptionKeyForPbes2() throws Exception {
        pinkSign.loadPrivateKey();
        ASN1Sequence der = PinkSignSupport.parseSequence(Fixtures.PBES2_PRIVATE_KEY);
        KeyIv keyIv = pinkSign.getPrivateKeyDecryptionKeyForPbes2(der);
        assertArrayEquals(Fixtures.PBES2_EXPECTED_KEY, keyIv.key());
        assertArrayEquals(Fixtures.PBES2_EXPECTED_IV, keyIv.iv());
    }

    @Test
    void testPkcs7SignedMessage() throws Exception {
        pinkSign.loadPrivateKey();
        assertArrayEquals(Fixtures.PKCS7_SIGNED_MSG, pinkSign.pkcs7SignedMessage(Fixtures.TEST_MSG));
    }

    @Test
    void testSeedCbc128Encrypt() throws Exception {
        assertArrayEquals(Fixtures.SEED_CIPHERTEXT, PinkSignFunctions.seedCbc128Encrypt(Fixtures.KEY, Fixtures.PLAINTEXT, Fixtures.IV));
    }

    @Test
    void testSeedCbc128EncryptProvider() throws Exception {
        assertArrayEquals(Fixtures.SEED_CIPHERTEXT, PinkSignFunctions.seedCbc128EncryptProvider(Fixtures.KEY, Fixtures.PLAINTEXT, Fixtures.IV));
    }

    @Test
    void testSeedCbc128EncryptPure() {
        assertArrayEquals(Fixtures.SEED_CIPHERTEXT, PinkSignFunctions.seedCbc128EncryptPure(Fixtures.KEY, Fixtures.PLAINTEXT, Fixtures.IV));
    }

    @Test
    void testSeedCbc128Decrypt() throws Exception {
        assertArrayEquals(Fixtures.PLAINTEXT, PinkSignFunctions.seedCbc128Decrypt(Fixtures.KEY, Fixtures.SEED_CIPHERTEXT, Fixtures.IV));
    }

    @Test
    void testSeedCbc128DecryptProvider() throws Exception {
        assertArrayEquals(Fixtures.PLAINTEXT, PinkSignFunctions.seedCbc128DecryptProvider(Fixtures.KEY, Fixtures.SEED_CIPHERTEXT, Fixtures.IV));
    }

    @Test
    void testSeedCbc128DecryptPure() {
        assertArrayEquals(Fixtures.PLAINTEXT, PinkSignFunctions.seedCbc128DecryptPure(Fixtures.KEY, Fixtures.SEED_CIPHERTEXT, Fixtures.IV));
    }

    @Test
    void testSeedGenerator() {
        assertEquals(16, PinkSignFunctions.seedGenerator(16).length);
        assertEquals(0, PinkSignFunctions.seedGenerator(0).length);
        for (byte value : PinkSignFunctions.seedGenerator(64)) {
            assertTrue(value != 0);
        }
    }

    @Test
    void testSeparateP12IntoNpki() throws Exception {
        NpkiMaterial material = PinkSignFunctions.separateP12IntoNpki(Fixtures.CERT_P12_DATA, Fixtures.CERT_PASSWORD);
        assertArrayEquals(Fixtures.CERT_PUBKEY_DER, material.publicKeyData());
        assertArrayEquals(Fixtures.decodeBase64(Fixtures.PLAIN_SIGN_PRI_B64), material.privateKeyData());
    }

    @Test
    void testInjectRandInPlainPrivateKey() throws Exception {
        assertEquals(Fixtures.PLAIN_SIGN_PRI_FULL_B64, PinkSignFunctions.injectRandInPlainPrivateKey(Fixtures.PLAIN_SIGN_PRI_B64, Fixtures.RAND));
    }

    @Test
    void testEncryptDecryptedPrivateKey() throws Exception {
        assertEquals(Fixtures.SIGNPRI_B64, PinkSignFunctions.encryptDecryptedPrivateKey(Fixtures.PLAIN_SIGN_PRI_FULL_B64, Fixtures.CERT_PASSWORD, Fixtures.SIGN_PRI_SALT_B64));
    }

    @Test
    void testEncryptDecryptedPrivateKeyHonorsIterationCount() throws Exception {
        String encrypted = PinkSignFunctions.encryptDecryptedPrivateKey(
            Fixtures.PLAIN_SIGN_PRI_FULL_B64,
            Fixtures.CERT_PASSWORD,
            Fixtures.SIGN_PRI_SALT_B64,
            1
        );
        ASN1Sequence der = PinkSignSupport.parseSequence(Fixtures.decodeBase64(encrypted));
        ASN1Sequence algorithmData = ASN1Sequence.getInstance(ASN1Sequence.getInstance(der.getObjectAt(0)).getObjectAt(1));
        assertEquals(java.math.BigInteger.ONE, ASN1Integer.getInstance(algorithmData.getObjectAt(1)).getValue());

        PinkSign cert = new PinkSign(Fixtures.CERT_PUBKEY_DER);
        cert.loadPrivateKey(Fixtures.decodeBase64(encrypted), Fixtures.CERT_PASSWORD);
        assertEquals(Fixtures.D, cert.privateKey().getPrivateExponent());
    }

    @Test
    void testSetKey() {
        assertArrayEquals(Fixtures.SEED_KEY, PinkSignFunctions.setKey(new byte[16]));
    }

    @Test
    void testProcessBlock() {
        assertArrayEquals(Fixtures.SEED_BLOCK_CIPHER, PinkSignFunctions.processBlock(true, Fixtures.SEED_BLOCK_KEY, Fixtures.SEED_BLOCK_PLAIN));
        assertArrayEquals(Fixtures.SEED_BLOCK_PLAIN, PinkSignFunctions.processBlock(false, Fixtures.SEED_BLOCK_KEY, Fixtures.SEED_BLOCK_CIPHER));
    }

    @Test
    void testProcessBlockProvider() throws Exception {
        byte[] encrypted = PinkSignFunctions.seedCbc128EncryptProvider(Fixtures.SEED_BLOCK_KEY, Fixtures.SEED_BLOCK_PLAIN, new byte[16]);
        assertArrayEquals(Fixtures.SEED_BLOCK_CIPHER, java.util.Arrays.copyOf(encrypted, 16));
    }

    @Test
    void testPureVsProvider() throws Exception {
        for (int iteration = 0; iteration < 100; iteration++) {
            byte[] randomBytes = PinkSignFunctions.seedGenerator(128);
            byte[] key = PinkSignFunctions.seedGenerator(16);
            byte[] iv = PinkSignFunctions.seedGenerator(16);
            byte[] encryptedPure = PinkSignFunctions.seedCbc128EncryptPure(key, randomBytes, iv);
            byte[] encryptedProvider = PinkSignFunctions.seedCbc128EncryptProvider(key, randomBytes, iv);
            assertArrayEquals(encryptedPure, encryptedProvider);
            byte[] decryptedPure = PinkSignFunctions.seedCbc128DecryptPure(key, encryptedPure, iv);
            byte[] decryptedProvider = PinkSignFunctions.seedCbc128DecryptProvider(key, encryptedProvider, iv);
            assertArrayEquals(decryptedPure, decryptedProvider);
            assertArrayEquals(randomBytes, decryptedPure);
        }
    }
}
