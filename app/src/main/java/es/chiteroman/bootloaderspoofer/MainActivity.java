package es.chiteroman.bootloaderspoofer;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.InputStream;

public class MainActivity extends Activity {

    private static final int PICK_XML_FILE = 1;
    private static final String PREFS_NAME = "keybox";

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
        try (InputStream is = getContentResolver().openInputStream(uri)) {
            if (is == null) {
                showError("Could not open file");
                return;
            }

            KeyboxParser.KeyboxData keyboxData = KeyboxParser.parse(is);

            if (keyboxData.ecPrivateKey == null && keyboxData.rsaPrivateKey == null) {
                showError("No valid keys found in the XML file");
                return;
            }

            saveKeybox(keyboxData);
            updateStatus();
            Toast.makeText(this, "Keybox imported successfully!", Toast.LENGTH_SHORT).show();

        } catch (Exception e) {
            showError("Failed to parse keybox:\n" + e.getMessage());
        }
    }

    private SharedPreferences getPrefs() {
        return getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
    }

    private void fixPermissions() {
        File dataDir = new File(getApplicationInfo().dataDir);
        File prefsDir = new File(dataDir, "shared_prefs");
        File prefsFile = new File(prefsDir, PREFS_NAME + ".xml");
        dataDir.setExecutable(true, false);
        dataDir.setReadable(true, false);
        prefsDir.setExecutable(true, false);
        prefsDir.setReadable(true, false);
        if (prefsFile.exists()) {
            prefsFile.setReadable(true, false);
        }
    }

    private void saveKeybox(KeyboxParser.KeyboxData data) {
        SharedPreferences.Editor editor = getPrefs().edit();
        editor.clear();
        editor.putBoolean("keybox_loaded", true);

        if (data.deviceId != null) {
            editor.putString("device_id", data.deviceId);
        }

        if (data.ecPrivateKey != null) {
            editor.putString("ec_private_key", data.ecPrivateKey);
            editor.putInt("ec_cert_count", data.ecCertificates.size());
            for (int i = 0; i < data.ecCertificates.size(); i++) {
                editor.putString("ec_cert_" + i, data.ecCertificates.get(i));
            }
        }

        if (data.rsaPrivateKey != null) {
            editor.putString("rsa_private_key", data.rsaPrivateKey);
            editor.putInt("rsa_cert_count", data.rsaCertificates.size());
            for (int i = 0; i < data.rsaCertificates.size(); i++) {
                editor.putString("rsa_cert_" + i, data.rsaCertificates.get(i));
            }
        }

        editor.commit();
        fixPermissions();
    }

    private void resetKeybox() {
        getPrefs().edit().clear().commit();
        fixPermissions();
        updateStatus();
        Toast.makeText(this, "Reset to default keybox", Toast.LENGTH_SHORT).show();
    }

    private void updateStatus() {
        SharedPreferences prefs = getPrefs();
        boolean loaded = prefs.getBoolean("keybox_loaded", false);

        if (loaded) {
            statusText.setText(R.string.status_custom);
            statusText.setTextColor(0xFF4CAF50);

            StringBuilder info = new StringBuilder();
            String deviceId = prefs.getString("device_id", null);
            if (deviceId != null) {
                info.append("Device ID: ").append(deviceId).append("\n");
            }

            boolean hasEc = prefs.getString("ec_private_key", null) != null;
            boolean hasRsa = prefs.getString("rsa_private_key", null) != null;

            if (hasEc) {
                int n = prefs.getInt("ec_cert_count", 0);
                info.append("EC key: \u2713 (").append(n).append(" certs)\n");
            }
            if (hasRsa) {
                int n = prefs.getInt("rsa_cert_count", 0);
                info.append("RSA key: \u2713 (").append(n).append(" certs)");
            }

            infoText.setText(info.toString().trim());
            infoText.setVisibility(View.VISIBLE);
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
}
