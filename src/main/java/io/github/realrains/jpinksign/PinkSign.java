package io.github.realrains.jpinksign;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.time.Instant;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public final class PinkSign {
    private Path publicKeyPath;
    private Path privateKeyPath;
    private Path pkcs12Path;
    private byte[] encryptedPrivateKeyData;
    private byte[] privateKeyPassword;
    private byte[] pkcs12Data;
    private byte[] publicData;

    private java.security.cert.X509Certificate publicCertificate;
    private RSAPublicKey publicKey;
    private RSAPrivateCrtKey privateKey;

    public PinkSign() {
    }

    public PinkSign(byte[] publicKeyData) throws PinkSignException {
        loadPublicKey(publicKeyData);
    }

    public PinkSign(Path publicKeyPath) throws PinkSignException {
        this.publicKeyPath = publicKeyPath;
        loadPublicKey();
    }

    public PinkSign(byte[] publicKeyData, byte[] privateKeyData, byte[] privateKeyPassword) throws PinkSignException {
        loadPublicKey(publicKeyData);
        this.encryptedPrivateKeyData = PinkSignSupport.copyNullable(privateKeyData);
        this.privateKeyPassword = PinkSignSupport.copyNullable(privateKeyPassword);
    }

    public PinkSign(Path publicKeyPath, Path privateKeyPath, byte[] privateKeyPassword) throws PinkSignException {
        this.publicKeyPath = publicKeyPath;
        this.privateKeyPath = privateKeyPath;
        this.privateKeyPassword = PinkSignSupport.copyNullable(privateKeyPassword);
        loadPublicKey();
        if (privateKeyPath != null && privateKeyPassword != null) {
            loadPrivateKey();
        }
    }

    public static PinkSign fromPkcs12(byte[] pkcs12Data, byte[] password) throws PinkSignException {
        PinkSign pinkSign = new PinkSign();
        pinkSign.pkcs12Data = PinkSignSupport.copyNullable(pkcs12Data);
        pinkSign.privateKeyPassword = PinkSignSupport.copyNullable(password);
        pinkSign.loadPkcs12(pkcs12Data);
        return pinkSign;
    }

    public static PinkSign fromPkcs12(Path pkcs12Path, byte[] password) throws PinkSignException {
        PinkSign pinkSign = new PinkSign();
        pinkSign.pkcs12Path = pkcs12Path;
        pinkSign.privateKeyPassword = PinkSignSupport.copyNullable(password);
        pinkSign.loadPkcs12();
        return pinkSign;
    }

    public void loadPublicKey() throws PinkSignException {
        if (publicData == null && publicKeyPath == null) {
            throw new IllegalArgumentException("Neither public key path nor public key data is set.");
        }
        if (publicData == null) {
            publicData = readAllBytes(publicKeyPath, "public key");
        }
        publicCertificate = PinkSignSupport.loadCertificate(publicData);
        publicKey = (RSAPublicKey) publicCertificate.getPublicKey();
    }

    public void loadPublicKey(Path path) throws PinkSignException {
        this.publicKeyPath = path;
        this.publicData = null;
        loadPublicKey();
    }

    public void loadPublicKey(byte[] publicKeyData) throws PinkSignException {
        if (publicKeyData == null) {
            throw new IllegalArgumentException("Public key data is required.");
        }
        this.publicData = Arrays.copyOf(publicKeyData, publicKeyData.length);
        this.publicKeyPath = null;
        loadPublicKey();
    }

    public void loadPrivateKey() throws PinkSignException {
        ensurePublicKeyLoaded("Public key must be loaded before private key.");
        if (encryptedPrivateKeyData == null && privateKeyPath == null) {
            throw new IllegalArgumentException("Private key path or private key data is not defined.");
        }
        if (privateKeyPassword == null) {
            throw new IllegalArgumentException("Private key password is not defined.");
        }
        if (encryptedPrivateKeyData == null) {
            encryptedPrivateKeyData = readAllBytes(privateKeyPath, "private key");
        }
        ASN1Sequence der = PinkSignSupport.parseSequence(encryptedPrivateKeyData);
        ASN1Sequence algorithmIdentifier = ASN1Sequence.getInstance(der.getObjectAt(0));
        ASN1ObjectIdentifier algorithmType = ASN1ObjectIdentifier.getInstance(algorithmIdentifier.getObjectAt(0));
        KeyIv keyIv;
        if (PinkSignSupport.ID_SEED_CBC_WITH_SHA1.equals(algorithmType)) {
            keyIv = getPrivateKeyDecryptionKeyForSeedCbcWithSha1(der);
        } else if (PinkSignSupport.ID_SEED_CBC.equals(algorithmType)) {
            keyIv = getPrivateKeyDecryptionKeyForSeedCbc(der);
        } else if (PinkSignSupport.ID_PBES2.equals(algorithmType)) {
            keyIv = getPrivateKeyDecryptionKeyForPbes2(der);
        } else {
            throw new IllegalArgumentException("Private key is not a supported K-PKI private key file.");
        }
        byte[] ciphertext = ASN1OctetString.getInstance(der.getObjectAt(1)).getOctets();
        loadPrivateKeyWithDecryptedData(PinkSignFunctions.seedCbc128Decrypt(keyIv.key(), ciphertext, keyIv.iv()));
    }

    public void loadPrivateKey(Path path, byte[] password) throws PinkSignException {
        this.privateKeyPath = path;
        this.privateKeyPassword = PinkSignSupport.copyNullable(password);
        this.encryptedPrivateKeyData = null;
        loadPrivateKey();
    }

    public void loadPrivateKey(byte[] encryptedPrivateKeyData, byte[] password) throws PinkSignException {
        if (encryptedPrivateKeyData == null) {
            throw new IllegalArgumentException("Private key data is required.");
        }
        this.encryptedPrivateKeyData = Arrays.copyOf(encryptedPrivateKeyData, encryptedPrivateKeyData.length);
        this.privateKeyPassword = PinkSignSupport.copyNullable(password);
        this.privateKeyPath = null;
        loadPrivateKey();
    }

    public void loadPkcs12() throws PinkSignException {
        if (pkcs12Data == null && pkcs12Path == null) {
            throw new IllegalArgumentException("PKCS#12 path or data is not defined.");
        }
        if (privateKeyPassword == null) {
            throw new IllegalArgumentException("PKCS#12 password is not defined.");
        }
        if (pkcs12Data == null) {
            pkcs12Data = readAllBytes(pkcs12Path, "PKCS#12");
        }
        loadPkcs12(pkcs12Data);
    }

    public void loadPkcs12(byte[] pkcs12Data) throws PinkSignException {
        if (pkcs12Data == null) {
            throw new IllegalArgumentException("PKCS#12 data is required.");
        }
        this.pkcs12Data = Arrays.copyOf(pkcs12Data, pkcs12Data.length);
        NpkiMaterial material = PinkSignSupport.separatePkcs12IntoNpki(pkcs12Data, privateKeyPassword);
        loadPublicKey(material.publicKeyData());
        loadPrivateKeyWithDecryptedData(material.privateKeyData());
    }

    public String cn() throws PinkSignException {
        ensurePublicKeyLoaded("Public key should be loaded before fetching CN.");
        String value = PinkSignSupport.firstRdnValue(certificateHolder().getSubject(), BCStyle.CN);
        return value == null ? "" : value;
    }

    public String issuer() throws PinkSignException {
        ensurePublicKeyLoaded("Public key should be loaded before fetching issuer.");
        return PinkSignSupport.firstRdnValue(certificateHolder().getIssuer(), BCStyle.O);
    }

    public String certClass() throws PinkSignException {
        ensurePublicKeyLoaded("Public key should be loaded before fetching certificate class.");
        return PinkSignSupport.firstRdnValue(certificateHolder().getIssuer(), BCStyle.CN);
    }

    public String certTypeOid() throws PinkSignException {
        ensurePublicKeyLoaded("Public key should be loaded before fetching certificate type.");
        Extension extension = certificateHolder().getExtension(Extension.certificatePolicies);
        if (extension == null) {
            return null;
        }
        CertificatePolicies policies = CertificatePolicies.getInstance(extension.getParsedValue());
        return policies.getPolicyInformation()[0].getPolicyIdentifier().getId();
    }

    public ValidityPeriod validDate() {
        ensurePublicKeyLoaded("Public key should be loaded before fetching valid date.");
        Instant notBefore = publicCertificate.getNotBefore().toInstant();
        Instant notAfter = publicCertificate.getNotAfter().toInstant();
        return new ValidityPeriod(notBefore, notAfter);
    }

    public BigInteger serialNumber() {
        ensurePublicKeyLoaded("Public key should be loaded before fetching serial number.");
        return publicCertificate.getSerialNumber();
    }

    public byte[] sign(byte[] message) throws PinkSignException {
        ensurePrivateKeyLoaded("Private key is required for signing.");
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new PinkSignException("Failed to sign message.", e);
        }
    }

    public boolean verify(byte[] signatureValue, byte[] message) throws PinkSignException {
        ensurePublicKeyLoaded("Public key is required for verification.");
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(message);
            return signature.verify(signatureValue);
        } catch (SignatureException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new PinkSignException("Failed to verify signature.", e);
        }
    }

    public byte[] decrypt(byte[] ciphertext) throws PinkSignException {
        ensurePrivateKeyLoaded("Private key is required for decryption.");
        return runRsa(Cipher.DECRYPT_MODE, privateKey, ciphertext, "Failed to decrypt message.");
    }

    public byte[] encrypt(byte[] message) throws PinkSignException {
        ensurePublicKeyLoaded("Public key is required for encryption.");
        return runRsa(Cipher.ENCRYPT_MODE, publicKey, message, "Failed to encrypt message.");
    }

    public byte[] pkcs7SignedMessage(byte[] message) throws PinkSignException {
        ensurePublicKeyLoaded("Public key is required for PKCS#7 signing.");
        byte[] signed = sign(message);
        ASN1Sequence certificateSequence = PinkSignSupport.parseSequence(publicData);
        ASN1Sequence tbsCertificate = ASN1Sequence.getInstance(certificateSequence.getObjectAt(0));

        ASN1Sequence digestAlgorithm = new DERSequence(new ASN1Encodable[] {
            PinkSignSupport.ID_SHA256,
            DERNull.INSTANCE,
        });

        ASN1Sequence contentInfo = new DERSequence(new ASN1Encodable[] {
            PinkSignSupport.ID_PKCS7_DATA,
            new DERTaggedObject(true, 0, new DEROctetString(message)),
        });

        ASN1Sequence issuerAndSerial = new DERSequence(new ASN1Encodable[] {
            tbsCertificate.getObjectAt(3),
            tbsCertificate.getObjectAt(1),
        });

        ASN1Sequence signatureAlgorithm = new DERSequence(new ASN1Encodable[] {
            PinkSignSupport.ID_PKCS1_ENCRYPTION,
            DERNull.INSTANCE,
        });

        ASN1Sequence signerInfo = new DERSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            issuerAndSerial,
            digestAlgorithm,
            signatureAlgorithm,
            new DEROctetString(signed),
        });

        ASN1Sequence signedData = new DERSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            new DERSet(digestAlgorithm),
            contentInfo,
            new DERTaggedObject(true, 0, certificateSequence),
            new DERSet(signerInfo),
        });

        ASN1Sequence output = new DERSequence(new ASN1Encodable[] {
            PinkSignSupport.ID_PKCS7_SIGNED_DATA,
            new DERTaggedObject(true, 0, signedData),
        });

        try {
            return output.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new PinkSignException("Failed to encode PKCS#7 signed message.", e);
        }
    }

    public KeyIv getPrivateKeyDecryptionKeyForSeedCbcWithSha1(ASN1Sequence der) throws PinkSignException {
        ensurePasswordLoaded();
        ASN1Sequence data = ASN1Sequence.getInstance(ASN1Sequence.getInstance(der.getObjectAt(0)).getObjectAt(1));
        byte[] salt = ASN1OctetString.getInstance(data.getObjectAt(0)).getOctets();
        int iterations = ASN1Integer.getInstance(data.getObjectAt(1)).getValue().intValueExact();
        byte[] derived = PinkSignSupport.pbkdf1(privateKeyPassword, salt, iterations, 20);
        byte[] key = Arrays.copyOf(derived, 16);
        byte[] iv = Arrays.copyOf(PinkSignSupport.sha1(Arrays.copyOfRange(derived, 16, 20)), 16);
        return new KeyIv(key, iv);
    }

    public KeyIv getPrivateKeyDecryptionKeyForSeedCbc(ASN1Sequence der) throws PinkSignException {
        ensurePasswordLoaded();
        ASN1Sequence data = ASN1Sequence.getInstance(ASN1Sequence.getInstance(der.getObjectAt(0)).getObjectAt(1));
        byte[] salt = ASN1OctetString.getInstance(data.getObjectAt(0)).getOctets();
        int iterations = ASN1Integer.getInstance(data.getObjectAt(1)).getValue().intValueExact();
        byte[] derived = PinkSignSupport.pbkdf1(privateKeyPassword, salt, iterations, 20);
        return new KeyIv(Arrays.copyOf(derived, 16), PinkSignSupport.DEFAULT_SEED_IV);
    }

    public KeyIv getPrivateKeyDecryptionKeyForPbes2(ASN1Sequence der) throws PinkSignException {
        ensurePasswordLoaded();
        ASN1Sequence algorithmParameters = ASN1Sequence.getInstance(ASN1Sequence.getInstance(der.getObjectAt(0)).getObjectAt(1));
        ASN1Sequence keyDerivationFunction = ASN1Sequence.getInstance(algorithmParameters.getObjectAt(0));
        ASN1Sequence keyDerivationParameters = ASN1Sequence.getInstance(keyDerivationFunction.getObjectAt(1));
        byte[] salt = ASN1OctetString.getInstance(keyDerivationParameters.getObjectAt(0)).getOctets();
        int iterations = ASN1Integer.getInstance(keyDerivationParameters.getObjectAt(1)).getValue().intValueExact();
        byte[] iv = ASN1OctetString.getInstance(ASN1Sequence.getInstance(algorithmParameters.getObjectAt(1)).getObjectAt(1)).getOctets();
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec keySpec = new PBEKeySpec(PinkSignSupport.passwordChars(privateKeyPassword), salt, iterations, 128);
            return new KeyIv(factory.generateSecret(keySpec).getEncoded(), iv);
        } catch (GeneralSecurityException e) {
            throw new PinkSignException("Failed to derive PBES2 key.", e);
        }
    }

    public RSAPublicKey publicKey() {
        return publicKey;
    }

    public RSAPrivateCrtKey privateKey() {
        return privateKey;
    }

    public byte[] publicData() {
        return PinkSignSupport.copyNullable(publicData);
    }

    public byte[] encryptedPrivateKeyData() {
        return PinkSignSupport.copyNullable(encryptedPrivateKeyData);
    }

    private void loadPrivateKeyWithDecryptedData(byte[] decryptedPrivateKeyData) throws PinkSignException {
        try {
            ASN1Sequence privateKeyInfo = PinkSignSupport.parseSequence(decryptedPrivateKeyData);
            byte[] rsaPrivateKeyDer = ASN1OctetString.getInstance(privateKeyInfo.getObjectAt(2)).getOctets();
            ASN1Sequence rsaPrivateKey = PinkSignSupport.parseSequence(rsaPrivateKeyDer);

            BigInteger modulus = ASN1Integer.getInstance(rsaPrivateKey.getObjectAt(1)).getPositiveValue();
            BigInteger publicExponent = ASN1Integer.getInstance(rsaPrivateKey.getObjectAt(2)).getPositiveValue();
            BigInteger privateExponent = ASN1Integer.getInstance(rsaPrivateKey.getObjectAt(3)).getPositiveValue();
            BigInteger prime1 = ASN1Integer.getInstance(rsaPrivateKey.getObjectAt(4)).getPositiveValue();
            BigInteger prime2 = ASN1Integer.getInstance(rsaPrivateKey.getObjectAt(5)).getPositiveValue();
            BigInteger exponent1 = privateExponent.remainder(prime1.subtract(BigInteger.ONE));
            BigInteger exponent2 = privateExponent.remainder(prime2.subtract(BigInteger.ONE));
            BigInteger coefficient = prime2.modInverse(prime1);

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                modulus,
                publicExponent,
                privateExponent,
                prime1,
                prime2,
                exponent1,
                exponent2,
                coefficient
            );
            privateKey = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (GeneralSecurityException e) {
            throw new PinkSignException("Failed to load decrypted private key.", e);
        }
    }

    private JcaX509CertificateHolder certificateHolder() throws PinkSignException {
        try {
            return new JcaX509CertificateHolder(publicCertificate);
        } catch (CertificateEncodingException e) {
            throw new PinkSignException("Failed to inspect certificate.", e);
        }
    }

    private byte[] runRsa(int mode, java.security.Key key, byte[] input, String message) throws PinkSignException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(mode, key);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new PinkSignException(message, e);
        }
    }

    private static byte[] readAllBytes(Path path, String label) throws PinkSignException {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new PinkSignException("Failed to read " + label + " file.", e);
        }
    }

    private void ensurePublicKeyLoaded(String message) {
        if (publicCertificate == null || publicKey == null) {
            throw new IllegalStateException(message);
        }
    }

    private void ensurePrivateKeyLoaded(String message) {
        if (privateKey == null) {
            throw new IllegalStateException(message);
        }
    }

    private void ensurePasswordLoaded() {
        if (privateKeyPassword == null) {
            throw new IllegalStateException("Private key password is required.");
        }
    }
}
