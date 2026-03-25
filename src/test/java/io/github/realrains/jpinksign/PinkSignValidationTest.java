package io.github.realrains.jpinksign;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class PinkSignValidationTest {
    @Test
    void testUnloadedAccessorsMayReturnNull() {
        PinkSign cert = new PinkSign();
        assertNull(cert.publicKey());
        assertNull(cert.privateKey());
        assertNull(cert.publicData());
        assertNull(cert.encryptedPrivateKeyData());
    }

    @Test
    void testLoadPublicKeyRequiresSource() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalArgumentException.class, cert::loadPublicKey);
    }

    @Test
    void testLoadPublicKeyRejectsNullData() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalArgumentException.class, () -> cert.loadPublicKey((byte[]) null));
    }

    @Test
    void testLoadPrivateKeyRequiresPublicKey() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalStateException.class, cert::loadPrivateKey);
    }

    @Test
    void testLoadPrivateKeyRequiresPassword() throws Exception {
        PinkSign cert = new PinkSign(Fixtures.CERT_PUBKEY_DER);
        assertThrows(IllegalArgumentException.class, () -> cert.loadPrivateKey(Fixtures.CERT_PRIKEY_DER, null));
    }

    @Test
    void testLoadPrivateKeyRejectsNullData() throws Exception {
        PinkSign cert = new PinkSign(Fixtures.CERT_PUBKEY_DER);
        assertThrows(IllegalArgumentException.class, () -> cert.loadPrivateKey((byte[]) null, Fixtures.CERT_PASSWORD));
    }

    @Test
    void testLoadPkcs12RejectsNullData() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalArgumentException.class, () -> cert.loadPkcs12((byte[]) null));
    }

    @Test
    void testCertTypeOidRequiresPublicKey() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalStateException.class, cert::certTypeOid);
    }

    @Test
    void testValidDateRequiresPublicKey() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalStateException.class, cert::validDate);
    }

    @Test
    void testSerialNumberRequiresPublicKey() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalStateException.class, cert::serialNumber);
    }

    @Test
    void testSignRequiresPrivateKey() throws Exception {
        PinkSign cert = new PinkSign(Fixtures.CERT_PUBKEY_DER);
        assertThrows(IllegalStateException.class, () -> cert.sign(Fixtures.ascii("data")));
    }

    @Test
    void testDecryptRequiresPrivateKey() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalStateException.class, () -> cert.decrypt(Fixtures.ascii("data")));
    }

    @Test
    void testVerifyRequiresPublicKey() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalStateException.class, () -> cert.verify(Fixtures.ascii("sig"), Fixtures.ascii("msg")));
    }

    @Test
    void testEncryptRequiresPublicKey() {
        PinkSign cert = new PinkSign();
        assertThrows(IllegalStateException.class, () -> cert.encrypt(Fixtures.ascii("msg")));
    }
}
