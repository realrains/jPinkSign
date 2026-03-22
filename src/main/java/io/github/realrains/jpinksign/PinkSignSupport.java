package io.github.realrains.jpinksign;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

final class PinkSignSupport {
    static final String BC_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    static final byte[] DEFAULT_SEED_IV = "0123456789012345".getBytes(StandardCharsets.US_ASCII);

    static final ASN1ObjectIdentifier ID_SEED_CBC = new ASN1ObjectIdentifier("1.2.410.200004.1.4");
    static final ASN1ObjectIdentifier ID_SEED_CBC_WITH_SHA1 = new ASN1ObjectIdentifier("1.2.410.200004.1.15");
    static final ASN1ObjectIdentifier ID_PBES2 = new ASN1ObjectIdentifier("1.2.840.113549.1.5.13");
    static final ASN1ObjectIdentifier ID_PKCS7_SIGNED_DATA = new ASN1ObjectIdentifier("1.2.840.113549.1.7.2");
    static final ASN1ObjectIdentifier ID_PKCS7_DATA = new ASN1ObjectIdentifier("1.2.840.113549.1.7.1");
    static final ASN1ObjectIdentifier ID_PKCS1_ENCRYPTION = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1");
    static final ASN1ObjectIdentifier ID_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
    static final ASN1ObjectIdentifier ID_KISA_NPKI_RAND_NUM = new ASN1ObjectIdentifier("1.2.410.200004.10.1.1.3");
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PinkSignSupport() {
    }

    static void ensureBouncyCastleProvider() {
        if (Security.getProvider(BC_PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static byte[] copyNullable(byte[] value) {
        return value == null ? null : Arrays.copyOf(value, value.length);
    }

    static void requireLength(byte[] value, int length, String name) {
        if (value == null || value.length != length) {
            throw new IllegalArgumentException(name + " must be " + length + " bytes.");
        }
    }

    static byte[] pbkdf1(byte[] password, byte[] salt, int iterationCount, int derivedKeyLength) throws PinkSignException {
        if (derivedKeyLength > 20) {
            throw new IllegalArgumentException("derived key too long");
        }
        requireLength(salt, 8, "Salt");
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] result = sha1.digest(concat(password, salt));
            for (int round = 2; round <= iterationCount; round++) {
                result = sha1.digest(result);
            }
            return Arrays.copyOf(result, derivedKeyLength);
        } catch (GeneralSecurityException e) {
            throw new PinkSignException("PBKDF1 derivation failed.", e);
        }
    }

    static NpkiMaterial separatePkcs12IntoNpki(byte[] p12Data, byte[] password) throws PinkSignException {
        if (p12Data == null) {
            throw new IllegalArgumentException("PKCS#12 data is required.");
        }
        if (password == null) {
            throw new IllegalArgumentException("PKCS#12 password is required.");
        }
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            char[] passwordChars = passwordChars(password);
            keyStore.load(new ByteArrayInputStream(p12Data), passwordChars);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!keyStore.isKeyEntry(alias)) {
                    continue;
                }
                Key key = keyStore.getKey(alias, passwordChars);
                Certificate certificate = keyStore.getCertificate(alias);
                if (!(key instanceof PrivateKey) || certificate == null) {
                    continue;
                }
                return new NpkiMaterial(certificate.getEncoded(), key.getEncoded());
            }
            throw new PinkSignException("PKCS#12 key entry was not found.");
        } catch (IOException | GeneralSecurityException e) {
            throw new PinkSignException("Failed to extract PKCS#12 material.", e);
        }
    }

    static X509Certificate loadCertificate(byte[] certificateDer) throws PinkSignException {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateDer));
        } catch (CertificateException e) {
            throw new PinkSignException("Failed to load X.509 certificate.", e);
        }
    }

    static ASN1Sequence parseSequence(byte[] encoded) throws PinkSignException {
        try (ASN1InputStream input = new ASN1InputStream(encoded)) {
            return ASN1Sequence.getInstance(input.readObject());
        } catch (IOException e) {
            throw new PinkSignException("Failed to parse ASN.1 sequence.", e);
        }
    }

    static String encryptDecryptedPrivateKey(String privateKeyBase64, byte[] password, String saltBase64, int iterationCount)
            throws PinkSignException {
        byte[] salt;
        if (saltBase64 == null) {
            salt = new byte[8];
            SECURE_RANDOM.nextBytes(salt);
        } else {
            salt = Base64.getDecoder().decode(saltBase64);
        }
        byte[] privateKey = Base64.getDecoder().decode(privateKeyBase64);
        byte[] derived = pbkdf1(password, salt, iterationCount, 20);
        byte[] key = Arrays.copyOf(derived, 16);
        byte[] iv = Arrays.copyOf(sha1(Arrays.copyOfRange(derived, 16, 20)), 16);
        byte[] ciphertext = PinkSignFunctions.seedCbc128Encrypt(key, privateKey, iv);

        ASN1EncodableVector algorithmData = new ASN1EncodableVector();
        algorithmData.add(new DEROctetString(salt));
        algorithmData.add(new ASN1Integer(2048));

        ASN1EncodableVector algorithmIdentifier = new ASN1EncodableVector();
        algorithmIdentifier.add(ID_SEED_CBC_WITH_SHA1);
        algorithmIdentifier.add(new DERSequence(algorithmData));

        ASN1EncodableVector npkiPrivateKey = new ASN1EncodableVector();
        npkiPrivateKey.add(new DERSequence(algorithmIdentifier));
        npkiPrivateKey.add(new DEROctetString(ciphertext));

        try {
            return Base64.getEncoder().encodeToString(new DERSequence(npkiPrivateKey).getEncoded(ASN1Encoding.DER));
        } catch (IOException e) {
            throw new PinkSignException("Failed to encode encrypted private key.", e);
        }
    }

    static String injectRandInPlainPrivateKey(String privateKeyBase64, byte[] randNum) throws PinkSignException {
        ASN1Sequence privateKey = parseSequence(Base64.getDecoder().decode(privateKeyBase64));

        ASN1EncodableVector randSequence = new ASN1EncodableVector();
        randSequence.add(ID_KISA_NPKI_RAND_NUM);
        randSequence.add(new DERSet(new DERBitString(randNum)));

        ASN1EncodableVector output = new ASN1EncodableVector();
        output.add(privateKey.getObjectAt(0));
        output.add(privateKey.getObjectAt(1));
        output.add(privateKey.getObjectAt(2));
        output.add(new DERTaggedObject(false, 0, new DERSet(new DERSequence(randSequence))));

        try {
            return Base64.getEncoder().encodeToString(new DERSequence(output).getEncoded(ASN1Encoding.DER));
        } catch (IOException e) {
            throw new PinkSignException("Failed to encode private key with random number.", e);
        }
    }

    static byte[] sha1(byte[] input) throws PinkSignException {
        try {
            return MessageDigest.getInstance("SHA-1").digest(input);
        } catch (GeneralSecurityException e) {
            throw new PinkSignException("SHA-1 digest failed.", e);
        }
    }

    static char[] passwordChars(byte[] password) {
        return new String(password, StandardCharsets.UTF_8).toCharArray();
    }

    static byte[] concat(byte[] first, byte[] second) {
        byte[] output = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, output, first.length, second.length);
        return output;
    }

    static String firstRdnValue(org.bouncycastle.asn1.x500.X500Name name, ASN1ObjectIdentifier oid) {
        for (org.bouncycastle.asn1.x500.RDN rdn : name.getRDNs()) {
            for (org.bouncycastle.asn1.x500.AttributeTypeAndValue value : rdn.getTypesAndValues()) {
                if (value.getType().equals(oid)) {
                    return org.bouncycastle.asn1.x500.style.IETFUtils.valueToString(value.getValue());
                }
            }
        }
        return null;
    }
}
