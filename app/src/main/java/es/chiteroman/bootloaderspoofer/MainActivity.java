package es.chiteroman.bootloaderspoofer;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class MainActivity extends Activity {

    private static final int PICK_XML_FILE = 1;
    private static final String KEYBOX_FILE = "keybox.xml";

    private TextView statusText;
    private TextView infoText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.status_text);
        infoText = findViewById(R.id.info_text);

        Button importBtn = findViewById(R.id.btn_import);
        Button resetBtn = findViewById(R.id.btn_reset);

        importBtn.setOnClickListener(v -> openFilePicker());
        resetBtn.setOnClickListener(v -> resetKeybox());

        updateStatus();
    }

    private void openFilePicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, PICK_XML_FILE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_XML_FILE && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                importKeybox(uri);
            }
        }
    }

    private void importKeybox(Uri uri) {
        try {
            byte[] xmlBytes;
            try (InputStream is = getContentResolver().openInputStream(uri)) {
                if (is == null) {
                    showError("Could not open file");
                    return;
                }
                xmlBytes = readAllBytes(is);
            }

            // Parse to validate
            KeyboxParser.KeyboxData data = KeyboxParser.parse(new ByteArrayInputStream(xmlBytes));
            if (data.ecPrivateKey == null && data.rsaPrivateKey == null) {
                showError("No valid keys found in the XML file");
                return;
            }

            // Save the raw XML
            File keyboxFile = getKeyboxFile();
            try (FileOutputStream fos = new FileOutputStream(keyboxFile)) {
                fos.write(xmlBytes);
            }

            fixPermissions();
            updateStatus();
            Toast.makeText(this, "Keybox imported successfully!", Toast.LENGTH_SHORT).show();

        } catch (Exception e) {
            showError("Failed to parse keybox:\n" + e.getMessage());
        }
    }

    private File getKeyboxFile() {
        return new File(getFilesDir(), KEYBOX_FILE);
    }

    private void fixPermissions() {
        File dataDir = new File(getApplicationInfo().dataDir);
        File filesDir = getFilesDir();
        File keyboxFile = getKeyboxFile();

        dataDir.setExecutable(true, false);
        dataDir.setReadable(true, false);
        filesDir.setExecutable(true, false);
        filesDir.setReadable(true, false);
        if (keyboxFile.exists()) {
            keyboxFile.setReadable(true, false);
        }
    }

    private void resetKeybox() {
        File keyboxFile = getKeyboxFile();
        if (keyboxFile.exists()) {
            keyboxFile.delete();
        }
        updateStatus();
        Toast.makeText(this, "Reset to default keybox", Toast.LENGTH_SHORT).show();
    }

    private void updateStatus() {
        File keyboxFile = getKeyboxFile();

        if (keyboxFile.exists()) {
            try {
                KeyboxParser.KeyboxData data = KeyboxParser.parse(keyboxFile);

                statusText.setText(R.string.status_custom);
                statusText.setTextColor(0xFF4CAF50);

                StringBuilder info = new StringBuilder();
                if (data.deviceId != null) {
                    info.append("Device ID: ").append(data.deviceId).append("\n");
                }
                if (data.ecPrivateKey != null) {
                    info.append("EC key: \u2713 (").append(data.ecCertificates.size()).append(" certs)\n");
                }
                if (data.rsaPrivateKey != null) {
                    info.append("RSA key: \u2713 (").append(data.rsaCertificates.size()).append(" certs)");
                }

                infoText.setText(info.toString().trim());
                infoText.setVisibility(View.VISIBLE);

            } catch (Exception e) {
                statusText.setText("Error reading keybox");
                statusText.setTextColor(0xFFCF6679);
                infoText.setVisibility(View.GONE);
            }
        } else {
            statusText.setText(R.string.status_default);
            statusText.setTextColor(0xFFBB86FC);
            infoText.setVisibility(View.GONE);
        }
    }

    private void showError(String message) {
        new AlertDialog.Builder(this)
                .setTitle("Error")
                .setMessage(message)
                .setPositiveButton("OK", null)
                .show();
    }

    private static byte[] readAllBytes(InputStream is) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int len;
        while ((len = is.read(buf)) != -1) {
            baos.write(buf, 0, len);
        }
        return baos.toByteArray();
    }
}
