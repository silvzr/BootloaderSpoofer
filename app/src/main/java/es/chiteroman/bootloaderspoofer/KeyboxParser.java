package es.chiteroman.bootloaderspoofer;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import static es.chiteroman.bootloaderspoofer.KeyboxData.Algorithm;

final class KeyboxParser {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private KeyboxParser() {
    }

    static Map<Algorithm, KeyboxData> parse(InputStream stream) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            try {
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            } catch (ParserConfigurationException ignored) {
                // Safe default even if feature unsupported
            }
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(stream);

            Map<Algorithm, KeyboxData> keyboxes = new HashMap<>();
            NodeList keyNodes = document.getElementsByTagName("Key");
            for (int i = 0; i < keyNodes.getLength(); i++) {
                Node node = keyNodes.item(i);
                if (!(node instanceof Element element)) continue;
                Algorithm algorithm = Algorithm.fromXml(element.getAttribute("algorithm"));
                if (algorithm == null) continue;

                String privateKeyPem = readChildText(element, "PrivateKey");
                List<String> certificatePems = readCertificatePems(element);
                KeyPair keyPair = parseKeyPair(privateKeyPem);
                List<X509Certificate> certificates = parseCertificates(certificatePems);
                if (keyPair != null && !certificates.isEmpty()) {
                    keyboxes.put(algorithm, new KeyboxData(algorithm, keyPair, certificates));
                }
            }
            return keyboxes;
        } catch (ParserConfigurationException | CertificateException e) {
            throw new IOException("Failed to parse keybox", e);
        } catch (Exception e) {
            throw new IOException("Failed to read keybox", e);
        }
    }

    private static List<String> readCertificatePems(Element element) {
        List<String> certs = new ArrayList<>();
        NodeList certificates = element.getElementsByTagName("Certificate");
        for (int i = 0; i < certificates.getLength(); i++) {
            Node node = certificates.item(i);
            String pem = node.getTextContent();
            if (pem != null && !pem.isEmpty()) {
                certs.add(pem);
            }
        }
        return certs;
    }

    private static String readChildText(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() == 0) return "";
        Node node = nodes.item(0);
        return node.getTextContent();
    }

    private static KeyPair parseKeyPair(String pem) throws IOException {
        String cleaned = normalizePem(pem);
        try (PEMParser parser = new PEMParser(new StringReader(cleaned))) {
            Object object = parser.readObject();
            if (object instanceof PEMKeyPair pemKeyPair) {
                return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
            }
        }
        return null;
    }

    private static List<X509Certificate> parseCertificates(List<String> pems) throws IOException, CertificateException {
        List<X509Certificate> certificates = new ArrayList<>();
        // Use default providers to avoid "X.509 not found for provider BC" on some Android builds.
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        for (String pem : pems) {
            String cleaned = normalizePem(pem);
            try (PemReader reader = new PemReader(new StringReader(cleaned))) {
                PemObject pemObject = reader.readPemObject();
                if (pemObject == null) continue;
                X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());
                certificates.add(converter.getCertificate(holder));
            }
        }
        return certificates;
    }

    private static String normalizePem(String pem) {
        return pem.replace("\r", "")
                .lines()
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .collect(Collectors.joining("\n"));
    }

    static String slurp(InputStream stream) throws IOException {
        StringBuilder builder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line).append('\n');
            }
        }
        return builder.toString();
    }
}
