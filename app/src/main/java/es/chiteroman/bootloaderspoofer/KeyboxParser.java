package es.chiteroman.bootloaderspoofer;

import android.util.Xml;

import org.xmlpull.v1.XmlPullParser;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class KeyboxParser {

    public static class KeyboxData {
        public String deviceId;
        public String ecPrivateKey;
        public final List<String> ecCertificates = new ArrayList<>();
        public String rsaPrivateKey;
        public final List<String> rsaCertificates = new ArrayList<>();
    }

    public static KeyboxData parse(InputStream inputStream) throws Exception {
        KeyboxData data = new KeyboxData();
        XmlPullParser parser = Xml.newPullParser();
        parser.setInput(inputStream, null);

        String currentAlgorithm = null;
        boolean inPrivateKey = false;
        boolean inCertificate = false;
        StringBuilder textBuilder = new StringBuilder();

        int eventType = parser.getEventType();
        while (eventType != XmlPullParser.END_DOCUMENT) {
            switch (eventType) {
                case XmlPullParser.START_TAG:
                    String name = parser.getName();
                    textBuilder.setLength(0);
                    if ("Keybox".equals(name)) {
                        data.deviceId = parser.getAttributeValue(null, "DeviceID");
                    } else if ("Key".equals(name)) {
                        currentAlgorithm = parser.getAttributeValue(null, "algorithm");
                    } else if ("PrivateKey".equals(name)) {
                        inPrivateKey = true;
                    } else if ("Certificate".equals(name)) {
                        inCertificate = true;
                    }
                    break;

                case XmlPullParser.TEXT:
                    textBuilder.append(parser.getText());
                    break;

                case XmlPullParser.END_TAG:
                    String endName = parser.getName();
                    if ("PrivateKey".equals(endName) && inPrivateKey) {
                        String pem = textBuilder.toString().trim();
                        if (!pem.isEmpty() && currentAlgorithm != null) {
                            if (isEc(currentAlgorithm)) {
                                data.ecPrivateKey = pem;
                            } else if (isRsa(currentAlgorithm)) {
                                data.rsaPrivateKey = pem;
                            }
                        }
                        inPrivateKey = false;
                    } else if ("Certificate".equals(endName) && inCertificate) {
                        String pem = textBuilder.toString().trim();
                        if (!pem.isEmpty() && currentAlgorithm != null) {
                            if (isEc(currentAlgorithm)) {
                                data.ecCertificates.add(pem);
                            } else if (isRsa(currentAlgorithm)) {
                                data.rsaCertificates.add(pem);
                            }
                        }
                        inCertificate = false;
                    } else if ("Key".equals(endName)) {
                        currentAlgorithm = null;
                    }
                    textBuilder.setLength(0);
                    break;
            }
            eventType = parser.next();
        }

        return data;
    }

    private static boolean isEc(String algo) {
        return "ecdsa".equalsIgnoreCase(algo) || "ec".equalsIgnoreCase(algo);
    }

    private static boolean isRsa(String algo) {
        return "rsa".equalsIgnoreCase(algo);
    }
}
