package es.chiteroman.bootloaderspoofer;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

final class KeyboxData {
    enum Algorithm {
        EC("ecdsa", "EC", "SHA256withECDSA"),
        RSA("rsa", "RSA", "SHA256withRSA");

        private final String xmlName;
        private final String keyAlgorithm;
        private final String signatureAlgorithm;

        Algorithm(String xmlName, String keyAlgorithm, String signatureAlgorithm) {
            this.xmlName = xmlName;
            this.keyAlgorithm = keyAlgorithm;
            this.signatureAlgorithm = signatureAlgorithm;
        }

        String getXmlName() {
            return xmlName;
        }

        String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        static Algorithm fromXml(String value) {
            for (Algorithm algorithm : values()) {
                if (algorithm.xmlName.equalsIgnoreCase(value)) {
                    return algorithm;
                }
            }
            return null;
        }
    }

    private final Algorithm algorithm;
    private final KeyPair keyPair;
    private final List<X509Certificate> chain;
    private final int keySizeBits;

    KeyboxData(Algorithm algorithm, KeyPair keyPair, List<X509Certificate> chain) {
        this.algorithm = algorithm;
        this.keyPair = keyPair;
        this.chain = Collections.unmodifiableList(chain);
        this.keySizeBits = resolveKeySize(keyPair);
    }

    Algorithm getAlgorithm() {
        return algorithm;
    }

    KeyPair getKeyPair() {
        return keyPair;
    }

    List<X509Certificate> getChain() {
        return chain;
    }

    int getKeySizeBits() {
        return keySizeBits;
    }

    private static int resolveKeySize(KeyPair pair) {
        if (pair.getPublic() instanceof RSAPublicKey rsaPublicKey) {
            return rsaPublicKey.getModulus().bitLength();
        }
        if (pair.getPublic() instanceof ECPublicKey ecPublicKey) {
            return ecPublicKey.getParams().getCurve().getField().getFieldSize();
        }
        return 0;
    }
}
