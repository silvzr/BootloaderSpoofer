package es.chiteroman.bootloaderspoofer;

import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.NonNull;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import es.chiteroman.bootloaderspoofer.KeyboxData.Algorithm;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedInterface.AfterHookCallback;
import io.github.libxposed.api.XposedInterface.BeforeHookCallback;
import io.github.libxposed.api.XposedInterface.Hooker;

public final class BootloaderSpooferModule extends XposedModule {
    private static final AtomicBoolean HOOKS_INSTALLED = new AtomicBoolean(false);
    private static final AtomicReference<byte[]> ATTESTATION_CHALLENGE = new AtomicReference<>(new byte[0]);
    private static volatile Map<Algorithm, KeyboxData> keyboxes = Map.of();

    public BootloaderSpooferModule(@NonNull XposedInterface base, @NonNull ModuleLoadedParam param) {
        super(base, param);
    }

    @Override
    public void onPackageLoaded(@NonNull PackageLoadedParam param) {
        if (!param.isFirstPackage()) return;
        if (getApplicationInfo().packageName.equals(param.getPackageName())) return;
        if (HOOKS_INSTALLED.get()) return;
        try {
            keyboxes = new KeyboxRepository(this).loadActiveKeybox();
            if (keyboxes.isEmpty()) {
                log("No keyboxes available; skipping hooks");
                return;
            }
            installHooks(param.getClassLoader());
            HOOKS_INSTALLED.set(true);
            log("BootloaderSpoofer hooks active for " + param.getPackageName());
        } catch (Throwable t) {
            log("Failed to install hooks: " + t.getMessage(), t);
        }
    }

    private void installHooks(ClassLoader classLoader) throws Exception {
        hookSystemFeatures(classLoader);
        hookSharedPreferences(classLoader);
        hookAttestationChallenge(classLoader);
        hookKeyPairGenerators();
        hookCertificateChain();
    }

    private void hookSystemFeatures(ClassLoader classLoader) throws Exception {
        Class<?> packageManagerClass = Class.forName("android.app.ApplicationPackageManager", false, classLoader);
        Method hasSystemFeature = packageManagerClass.getDeclaredMethod("hasSystemFeature", String.class);
        Method hasSystemFeatureWithFlags = packageManagerClass.getDeclaredMethod("hasSystemFeature", String.class, int.class);
        hook(hasSystemFeature, SystemFeatureHook.class);
        hook(hasSystemFeatureWithFlags, SystemFeatureHook.class);
    }

    public static final class SystemFeatureHook implements Hooker {
        public static void before(@NonNull BeforeHookCallback callback) {
            Object[] args = callback.getArgs();
            if (args.length == 0) return;
            String feature = (String) args[0];
            if (PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(feature)
                    || PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(feature)
                    || "android.software.device_id_attestation".equals(feature)) {
                callback.returnAndSkip(Boolean.FALSE);
            }
        }
    }

    private void hookSharedPreferences(ClassLoader classLoader) throws Exception {
        Class<?> sharedPreferencesImpl = Class.forName("android.app.SharedPreferencesImpl", false, classLoader);
        Method getBoolean = sharedPreferencesImpl.getDeclaredMethod("getBoolean", String.class, boolean.class);
        hook(getBoolean, PreferAttestKeyHook.class);
    }

    public static final class PreferAttestKeyHook implements Hooker {
        public static void before(@NonNull BeforeHookCallback callback) {
            Object[] args = callback.getArgs();
            if (args.length < 1) return;
            String key = (String) args[0];
            if ("prefer_attest_key".equals(key)) {
                callback.returnAndSkip(Boolean.FALSE);
            }
        }
    }

    private void hookAttestationChallenge(ClassLoader classLoader) throws Exception {
        Class<?> builderClass = KeyGenParameterSpec.Builder.class;
        Method setChallenge = builderClass.getDeclaredMethod("setAttestationChallenge", byte[].class);
        hook(setChallenge, AttestationChallengeHook.class);
    }

    public static final class AttestationChallengeHook implements Hooker {
        public static void before(@NonNull BeforeHookCallback callback) {
            Object[] args = callback.getArgs();
            if (args.length > 0 && args[0] instanceof byte[] bytes) {
                ATTESTATION_CHALLENGE.set(Arrays.copyOf(bytes, bytes.length));
            }
        }
    }

    private void hookKeyPairGenerators() throws Exception {
        KeyboxData ecBox = keyboxes.get(Algorithm.EC);
        if (ecBox != null) {
            KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            Method generate = ecGenerator.getClass().getDeclaredMethod("generateKeyPair");
            hook(generate, EcGenerateHook.class);
        }
        KeyboxData rsaBox = keyboxes.get(Algorithm.RSA);
        if (rsaBox != null) {
            KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            Method generate = rsaGenerator.getClass().getDeclaredMethod("generateKeyPair");
            hook(generate, RsaGenerateHook.class);
        }
    }

    public static final class EcGenerateHook implements Hooker {
        public static void before(@NonNull BeforeHookCallback callback) {
            KeyboxData data = keyboxes.get(Algorithm.EC);
            if (data != null) {
                callback.returnAndSkip(data.getKeyPair());
            }
        }
    }

    public static final class RsaGenerateHook implements Hooker {
        public static void before(@NonNull BeforeHookCallback callback) {
            KeyboxData data = keyboxes.get(Algorithm.RSA);
            if (data != null) {
                callback.returnAndSkip(data.getKeyPair());
            }
        }
    }

    private void hookCertificateChain() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Field keyStoreSpiField = KeyStore.class.getDeclaredField("keyStoreSpi");
        keyStoreSpiField.setAccessible(true);
        KeyStoreSpi keyStoreSpi = (KeyStoreSpi) keyStoreSpiField.get(keyStore);
        Method getChain = keyStoreSpi.getClass().getDeclaredMethod("engineGetCertificateChain", String.class);
        hook(getChain, CertificateChainHook.class);
    }

    public static final class CertificateChainHook implements Hooker {
        public static void after(@NonNull AfterHookCallback callback) {
            Certificate[] original = (Certificate[]) callback.getResult();
            Algorithm algorithm = resolveAlgorithm(original);
            if (algorithm == null) {
                algorithm = keyboxes.containsKey(Algorithm.EC) ? Algorithm.EC : Algorithm.RSA;
            }
            KeyboxData data = keyboxes.get(algorithm);
            if (data == null) return;

            try {
                X509Certificate attestationCert = AttestationCertificateFactory.buildLeaf(ATTESTATION_CHALLENGE.get(), data);
                List<Certificate> chain = new ArrayList<>();
                chain.add(attestationCert);
                chain.addAll(data.getChain());
                callback.setResult(chain.toArray(new Certificate[0]));
            } catch (Throwable t) {
                // Leave original result on failure
            }
        }

        private static Algorithm resolveAlgorithm(Certificate[] certificates) {
            if (certificates == null || certificates.length == 0) return null;
            Certificate certificate = certificates[0];
            if (certificate instanceof X509Certificate x509) {
                String algorithm = x509.getPublicKey().getAlgorithm();
                if (KeyProperties.KEY_ALGORITHM_EC.equalsIgnoreCase(algorithm)) return Algorithm.EC;
                if (KeyProperties.KEY_ALGORITHM_RSA.equalsIgnoreCase(algorithm)) return Algorithm.RSA;
            }
            return null;
        }
    }
}
