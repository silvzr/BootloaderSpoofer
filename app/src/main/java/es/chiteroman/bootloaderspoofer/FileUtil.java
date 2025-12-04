package es.chiteroman.bootloaderspoofer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

final class FileUtil {
    private FileUtil() {
    }

    static void copyToFile(InputStream inputStream, File target) throws IOException {
        if (target.getParentFile() != null && !target.getParentFile().exists()) {
            //noinspection ResultOfMethodCallIgnored
            target.getParentFile().mkdirs();
        }
        try (OutputStream outputStream = new FileOutputStream(target)) {
            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, read);
            }
            outputStream.flush();
        }
    }
}
