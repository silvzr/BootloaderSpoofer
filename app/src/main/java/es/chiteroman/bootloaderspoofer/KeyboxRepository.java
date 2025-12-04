package es.chiteroman.bootloaderspoofer;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import es.chiteroman.bootloaderspoofer.KeyboxData.Algorithm;
import io.github.libxposed.api.XposedInterface;

public final class KeyboxRepository {
    static final String IMPORTED_FILE_NAME = "imported_keybox.xml";
    private static final String DEFAULT_ASSET_PATH = "assets/aosp.xml";

    private final XposedInterface xposed;

    public KeyboxRepository(XposedInterface xposed) {
        this.xposed = xposed;
    }

    public KeyboxRepository() {
        this.xposed = null;
    }

    public Map<Algorithm, KeyboxData> loadActiveKeybox() throws IOException {
        try (InputStream stream = openPreferredKeybox()) {
            if (stream == null) return Map.of();
            return KeyboxParser.parse(stream);
        }
    }

    public boolean hasImportedKeybox(Context context) {
        File file = new File(context.getFilesDir(), IMPORTED_FILE_NAME);
        return file.exists();
    }

    public void saveImportedKeybox(Context context, InputStream source) throws IOException {
        File target = new File(context.getFilesDir(), IMPORTED_FILE_NAME);
        FileUtil.copyToFile(source, target);
    }

    public boolean deleteImportedKeybox(Context context) {
        File target = new File(context.getFilesDir(), IMPORTED_FILE_NAME);
        return !target.exists() || target.delete();
    }

    private InputStream openPreferredKeybox() throws IOException {
        InputStream imported = openRemoteImported();
        if (imported != null) return imported;
        return openBundledDefault();
    }

    private InputStream openRemoteImported() {
        if (xposed == null) return null;
        try {
            String[] files = xposed.listRemoteFiles();
            for (String name : files) {
                if (IMPORTED_FILE_NAME.equals(name)) {
                    ParcelFileDescriptor pfd = xposed.openRemoteFile(name);
                    return new FileInputStream(pfd.getFileDescriptor());
                }
            }
        } catch (Throwable ignored) {
            // Ignore and fall back to default asset
        }
        return null;
    }

    private InputStream openBundledDefault() throws IOException {
        if (xposed == null) {
            return KeyboxRepository.class.getClassLoader().getResourceAsStream(DEFAULT_ASSET_PATH);
        }
        ApplicationInfo info = xposed.getApplicationInfo();
        ZipFile zipFile = new ZipFile(info.sourceDir);
        ZipEntry entry = zipFile.getEntry(DEFAULT_ASSET_PATH);
        if (entry == null) {
            zipFile.close();
            throw new IOException("Default keybox asset missing");
        }
        return new ZipInputStreamWrapper(zipFile, entry);
    }

    private static final class ZipInputStreamWrapper extends InputStream {
        private final ZipFile zipFile;
        private final InputStream delegate;

        ZipInputStreamWrapper(ZipFile zipFile, ZipEntry entry) throws IOException {
            this.zipFile = zipFile;
            this.delegate = zipFile.getInputStream(entry);
        }

        @Override
        public int read() throws IOException {
            return delegate.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            return delegate.read(b, off, len);
        }

        @Override
        public int read(byte[] b) throws IOException {
            return delegate.read(b);
        }

        @Override
        public void close() throws IOException {
            try {
                delegate.close();
            } finally {
                zipFile.close();
            }
        }
    }
}
