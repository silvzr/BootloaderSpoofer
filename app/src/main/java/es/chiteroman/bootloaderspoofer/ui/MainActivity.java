package es.chiteroman.bootloaderspoofer.ui;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;

import java.io.IOException;
import java.io.InputStream;

import es.chiteroman.bootloaderspoofer.KeyboxRepository;
import es.chiteroman.bootloaderspoofer.R;

public class MainActivity extends AppCompatActivity {
    private static final String MIME_XML = "application/xml";

    private CardView statusCard;
    private TextView statusText;
    private final KeyboxRepository repository = new KeyboxRepository();

    private final ActivityResultLauncher<String[]> importLauncher =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), this::onImportResult);

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusCard = findViewById(R.id.statusCard);
        statusText = findViewById(R.id.statusText);
        Button importButton = findViewById(R.id.importButton);
        Button deleteButton = findViewById(R.id.deleteButton);

        importButton.setOnClickListener(v -> launchPicker());
        deleteButton.setOnClickListener(v -> handleDelete());

        updateStatus();
    }

    private void launchPicker() {
        try {
            importLauncher.launch(new String[]{MIME_XML, "text/xml", "application/octet-stream"});
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, R.string.import_not_supported, Toast.LENGTH_LONG).show();
        }
    }

    private void onImportResult(@Nullable Uri uri) {
        if (uri == null) return;
        try (InputStream stream = getContentResolver().openInputStream(uri)) {
            if (stream == null) throw new IOException("Empty file");
            repository.saveImportedKeybox(this, stream);
            takePersistablePermissions(uri);
            Toast.makeText(this, R.string.import_success, Toast.LENGTH_SHORT).show();
        } catch (IOException e) {
            Toast.makeText(this, getString(R.string.import_failed, e.getMessage()), Toast.LENGTH_LONG).show();
        }
        updateStatus();
    }

    private void takePersistablePermissions(Uri uri) {
        final int flags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION;
        try {
            getContentResolver().takePersistableUriPermission(uri, flags);
        } catch (SecurityException ignored) {
            // Best effort
        }
    }

    private void handleDelete() {
        if (repository.deleteImportedKeybox(this)) {
            Toast.makeText(this, R.string.delete_success, Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, R.string.delete_failed, Toast.LENGTH_LONG).show();
        }
        updateStatus();
    }

    private void updateStatus() {
        boolean hasImport = repository.hasImportedKeybox(this);
        if (hasImport) {
            statusCard.setCardBackgroundColor(getColor(R.color.status_green));
            statusText.setText(R.string.status_imported);
        } else {
            statusCard.setCardBackgroundColor(getColor(R.color.status_yellow));
            statusText.setText(R.string.status_default);
        }
    }
}
