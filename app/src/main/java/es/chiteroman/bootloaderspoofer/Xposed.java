package es.chiteroman.bootloaderspoofer;

import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public final class Xposed extends XposedModule {

    private static KeyPair keyPair_EC;
    private static KeyPair keyPair_RSA;
    private static final LinkedList<Certificate> certs_EC = new LinkedList<>();
    private static final LinkedList<Certificate> certs_RSA = new LinkedList<>();
    private static byte[] attestationChallengeBytes = new byte[1];
    private static boolean keyboxLoaded = false;

    public Xposed(XposedInterface base, ModuleLoadedParam param) {
        super(base, param);
    }

    private void loadKeybox() {
        try {
            SharedPreferences prefs = getRemotePreferences("keybox");
            if (!prefs.getBoolean("keybox_loaded", false)) {
                log("BootloaderSpoofer: No keybox configured");
                return;
            }

            String ecKey = prefs.getString("ec_private_key", null);
            if (ecKey != null) {
                keyPair_EC = parseKeyPair(ecKey);
                certs_EC.clear();
                int count = prefs.getInt("ec_cert_count", 0);
                for (int i = 0; i < count; i++) {
                    String cert = prefs.getString("ec_cert_" + i, null);
                    if (cert != null) certs_EC.add(parseCert(cert));
                }
            }

            String rsaKey = prefs.getString("rsa_private_key", null);
            if (rsaKey != null) {
                keyPair_RSA = parseKeyPair(rsaKey);
                certs_RSA.clear();
                int count = prefs.getInt("rsa_cert_count", 0);
                for (int i = 0; i < count; i++) {
                    String cert = prefs.getString("rsa_cert_" + i, null);
                    if (cert != null) certs_RSA.add(parseCert(cert));
                }
            }

            keyboxLoaded = (keyPair_EC != null || keyPair_RSA != null);
            if (keyboxLoaded) {
                log("BootloaderSpoofer: Custom keybox loaded successfully");
            }
        } catch (Throwable t) {
            log("BootloaderSpoofer: Failed to load keybox");
            log(t.toString());
        }
    }

    private static KeyPair parseKeyPair(String key) throws Throwable {
        Object object;
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            object = parser.readObject();
        }
        PEMKeyPair pemKeyPair = (PEMKeyPair) object;
        return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
    }

    private static Certificate parseCert(String cert) throws Throwable {
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }
        X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static Extension addHackedExtension(Extension extension) {
        try {
            ASN1Sequence keyDescription = ASN1Sequence.getInstance(extension.getExtnValue().getOctets());

            ASN1EncodableVector teeEnforcedEncodables = new ASN1EncodableVector();

            ASN1Sequence teeEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(7).toASN1Primitive();

            for (ASN1Encodable asn1Encodable : teeEnforcedAuthList) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                if (taggedObject.getTagNo() == 704) continue;
                teeEnforcedEncodables.add(taggedObject);
            }

            SecureRandom random = new SecureRandom();
            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];
            random.nextBytes(bytes1);
            random.nextBytes(bytes2);

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(bytes1), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(bytes2)};
            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);
            ASN1TaggedObject rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            teeEnforcedEncodables.add(rootOfTrust);

            var attestationVersion = keyDescription.getObjectAt(0);
            var attestationSecurityLevel = keyDescription.getObjectAt(1);
            var keymasterVersion = keyDescription.getObjectAt(2);
            var keymasterSecurityLevel = keyDescription.getObjectAt(3);
            var attestationChallenge = keyDescription.getObjectAt(4);
            var uniqueId = keyDescription.getObjectAt(5);
            var softwareEnforced = keyDescription.getObjectAt(6);
            var teeEnforced = new DERSequence(teeEnforcedEncodables);

            ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};
            ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);
            ASN1OctetString keyDescriptionOctetStr = new DEROctetString(keyDescriptionHackSeq);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);
        } catch (Throwable ignored) {
        }
        return extension;
    }

    private static Extension createHackedExtensions() {
        try {
            SecureRandom random = new SecureRandom();
            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];
            random.nextBytes(bytes1);
            random.nextBytes(bytes2);

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(bytes1), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(bytes2)};
            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            ASN1Integer[] purposesArray = {new ASN1Integer(0), new ASN1Integer(1), new ASN1Integer(2), new ASN1Integer(3), new ASN1Integer(4), new ASN1Integer(5)};
            ASN1Encodable[] digests = {new ASN1Integer(1), new ASN1Integer(2), new ASN1Integer(3), new ASN1Integer(4), new ASN1Integer(5), new ASN1Integer(6)};

            var Apurpose = new DERSet(purposesArray);
            var Aalgorithm = new ASN1Integer(3);
            var AkeySize = new ASN1Integer(256);
            var Adigest = new DERSet(digests);
            var AecCurve = new ASN1Integer(1);
            var AnoAuthRequired = DERNull.INSTANCE;
            var AosVersion = new ASN1Integer(130000);
            var AosPatchLevel = new ASN1Integer(202401);
            var AcreationDateTime = new ASN1Integer(System.currentTimeMillis());
            var Aorigin = new ASN1Integer(0);

            var purpose = new DERTaggedObject(true, 1, Apurpose);
            var algorithm = new DERTaggedObject(true, 2, Aalgorithm);
            var keySize = new DERTaggedObject(true, 3, AkeySize);
            var digest = new DERTaggedObject(true, 5, Adigest);
            var ecCurve = new DERTaggedObject(true, 10, AecCurve);
            var noAuthRequired = new DERTaggedObject(true, 503, AnoAuthRequired);
            var creationDateTime = new DERTaggedObject(true, 701, AcreationDateTime);
            var origin = new DERTaggedObject(true, 702, Aorigin);
            var rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            var osVersion = new DERTaggedObject(true, 705, AosVersion);
            var osPatchLevel = new DERTaggedObject(true, 706, AosPatchLevel);

            ASN1Encodable[] teeEnforcedEncodables = {purpose, algorithm, keySize, digest, ecCurve, noAuthRequired, creationDateTime, origin, rootOfTrust, osVersion, osPatchLevel};

            ASN1Integer attestationVersion = new ASN1Integer(4);
            ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1);
            ASN1Integer keymasterVersion = new ASN1Integer(41);
            ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1);
            ASN1OctetString attestationChallenge = new DEROctetString(attestationChallengeBytes);
            ASN1OctetString uniqueId = new DEROctetString("".getBytes());
            ASN1Sequence softwareEnforced = new DERSequence();
            ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

            ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};
            ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);
            ASN1OctetString keyDescriptionOctetStr = new DEROctetString(keyDescriptionHackSeq);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static Certificate createLeafCert() {
        try {
            long now = System.currentTimeMillis();
            Date notBefore = new Date(now);

            Calendar calendar = Calendar.getInstance();
            calendar.setTime(notBefore);
            calendar.add(Calendar.HOUR, 1);

            Date notAfter = calendar.getTime();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(new X500Name("CN=chiteroman"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=Android Keystore Key"), keyPair_EC.getPublic());

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
            certBuilder.addExtension(createHackedExtensions());

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair_EC.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);

            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static Certificate hackLeafExistingCert(Certificate certificate) {
        try {
            X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());

            KeyPair keyPair;
            if (KeyProperties.KEY_ALGORITHM_EC.equals(certificate.getPublicKey().getAlgorithm())) {
                keyPair = keyPair_EC;
            } else {
                keyPair = keyPair_RSA;
            }

            long now = System.currentTimeMillis();
            Date notBefore = new Date(now);

            Calendar calendar = Calendar.getInstance();
            calendar.setTime(notBefore);
            calendar.add(Calendar.HOUR, 1);

            Date notAfter = calendar.getTime();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(certificateHolder.getIssuer(), certificateHolder.getSerialNumber(), notBefore, notAfter, certificateHolder.getSubject(), keyPair.getPublic());

            for (Object extensionOID : certificateHolder.getExtensionOIDs()) {
                ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier) extensionOID;
                if ("1.3.6.1.4.1.11129.2.1.17".equals(identifier.getId())) continue;
                certBuilder.addExtension(certificateHolder.getExtension(identifier));
            }

            Extension extension = certificateHolder.getExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"));
            certBuilder.addExtension(addHackedExtension(extension));

            ContentSigner contentSigner;
            if (KeyProperties.KEY_ALGORITHM_EC.equals(certificate.getPublicKey().getAlgorithm())) {
                contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
            } else {
                contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            }

            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Throwable ignored) {
        }
        return certificate;
    }

    // --- Hooker classes for the new API ---

    public static class SystemFeatureHooker implements XposedInterface.Hooker {
        public static void before(XposedInterface.BeforeHookCallback callback) {
            if (!keyboxLoaded) return;
            String featureName = (String) callback.getArgs()[0];
            if (PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(featureName)
                    || PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(featureName)
                    || "android.software.device_id_attestation".equals(featureName)) {
                callback.returnAndSkip(Boolean.FALSE);
            }
        }
    }

    public static class PreferAttestKeyHooker implements XposedInterface.Hooker {
        public static void before(XposedInterface.BeforeHookCallback callback) {
            if (!keyboxLoaded) return;
            String key = (String) callback.getArgs()[0];
            if ("prefer_attest_key".equals(key)) {
                callback.returnAndSkip(Boolean.FALSE);
            }
        }
    }

    public static class AttestationChallengeHooker implements XposedInterface.Hooker {
        public static void before(XposedInterface.BeforeHookCallback callback) {
            if (!keyboxLoaded) return;
            attestationChallengeBytes = (byte[]) callback.getArgs()[0];
        }
    }

    public static class GenerateKeyPairECHooker implements XposedInterface.Hooker {
        public static void before(XposedInterface.BeforeHookCallback callback) {
            if (!keyboxLoaded || keyPair_EC == null) return;
            callback.returnAndSkip(keyPair_EC);
        }
    }

    public static class GenerateKeyPairRSAHooker implements XposedInterface.Hooker {
        public static void before(XposedInterface.BeforeHookCallback callback) {
            if (!keyboxLoaded || keyPair_RSA == null) return;
            callback.returnAndSkip(keyPair_RSA);
        }
    }

    public static class CertificateChainHooker implements XposedInterface.Hooker {
        public static void after(XposedInterface.AfterHookCallback callback) {
            if (!keyboxLoaded) return;

            Certificate[] certificates = (Certificate[]) callback.getResult();
            LinkedList<Certificate> certificateList = new LinkedList<>();

            if (certificates == null) {
                if (keyPair_EC == null || certs_EC.isEmpty()) return;
                certificateList.addAll(certs_EC);
                certificateList.addFirst(createLeafCert());
            } else {
                if (!(certificates[0] instanceof X509Certificate x509Certificate)) return;

                byte[] bytes = x509Certificate.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
                if (bytes == null || bytes.length == 0) return;

                String algorithm = x509Certificate.getPublicKey().getAlgorithm();
                if (KeyProperties.KEY_ALGORITHM_EC.equals(algorithm)) {
                    if (certs_EC.isEmpty()) return;
                    certificateList.addAll(certs_EC);
                } else if (KeyProperties.KEY_ALGORITHM_RSA.equals(algorithm)) {
                    if (certs_RSA.isEmpty()) return;
                    certificateList.addAll(certs_RSA);
                }
                certificateList.addFirst(hackLeafExistingCert(x509Certificate));
            }

            callback.setResult(certificateList.toArray(new Certificate[0]));
        }
    }

    @Override
    public void onPackageLoaded(XposedModuleInterface.PackageLoadedParam param) {
        if (!param.isFirstPackage()) return;

        loadKeybox();

        if (!keyboxLoaded) {
            log("BootloaderSpoofer: No keybox loaded, hooks disabled");
            return;
        }

        try {
            ClassLoader cl = param.getClassLoader();

            // Hook hasSystemFeature
            Class<?> pmClass = cl.loadClass("android.app.ApplicationPackageManager");
            try {
                Method hasSystemFeature1 = pmClass.getMethod("hasSystemFeature", String.class);
                hook(hasSystemFeature1, SystemFeatureHooker.class);
            } catch (NoSuchMethodException ignored) {}
            try {
                Method hasSystemFeature2 = pmClass.getMethod("hasSystemFeature", String.class, int.class);
                hook(hasSystemFeature2, SystemFeatureHooker.class);
            } catch (NoSuchMethodException ignored) {}

            // Hook SharedPreferencesImpl.getBoolean
            Class<?> spClass = cl.loadClass("android.app.SharedPreferencesImpl");
            try {
                Method getBoolean = spClass.getMethod("getBoolean", String.class, boolean.class);
                hook(getBoolean, PreferAttestKeyHooker.class);
            } catch (NoSuchMethodException ignored) {}
        } catch (Throwable t) {
            log("BootloaderSpoofer: " + t);
        }

        // Hook setAttestationChallenge
        try {
            Method setAttestationChallenge = KeyGenParameterSpec.Builder.class.getMethod("setAttestationChallenge", byte[].class);
            hook(setAttestationChallenge, AttestationChallengeHooker.class);
        } catch (Throwable t) {
            log("BootloaderSpoofer: " + t);
        }

        // Hook generateKeyPair
        try {
            if (keyPair_EC != null) {
                KeyPairGeneratorSpi kpgEC = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                Method generateKeyPairEC = kpgEC.getClass().getMethod("generateKeyPair");
                hook(generateKeyPairEC, GenerateKeyPairECHooker.class);
            }
            if (keyPair_RSA != null) {
                KeyPairGeneratorSpi kpgRSA = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                Method generateKeyPairRSA = kpgRSA.getClass().getMethod("generateKeyPair");
                hook(generateKeyPairRSA, GenerateKeyPairRSAHooker.class);
            }
        } catch (Throwable t) {
            log("BootloaderSpoofer: " + t);
        }

        // Hook engineGetCertificateChain
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) getField(keyStore, "keyStoreSpi");
            Method engineGetCertificateChain = keyStoreSpi.getClass().getMethod("engineGetCertificateChain", String.class);
            hook(engineGetCertificateChain, CertificateChainHooker.class);
        } catch (Throwable t) {
            log("BootloaderSpoofer: " + t);
        }
    }

    private static Object getField(Object obj, String fieldName) throws Throwable {
        var field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }
}
