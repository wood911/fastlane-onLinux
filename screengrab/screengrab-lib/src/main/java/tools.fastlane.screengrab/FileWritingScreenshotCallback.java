package tools.fastlane.screengrab;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Bitmap;
import android.os.Build;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Default {@link ScreenshotCallback} implementation that stores the captured Bitmap on the file
 * system in the structure that the Screengrab command-line utility expects.
 */
public class FileWritingScreenshotCallback implements ScreenshotCallback {
    private static final String TAG = "Screengrab";

    protected static final String NAME_SEPARATOR = "_";
    protected static final String EXTENSION = ".png";
    private static final int FULL_QUALITY = 100;
    private static final String SCREENGRAB_DIR_NAME = "screengrab";
    private static final String APPEND_TIMESTAMP_CONFIG_KEY = "appendTimestamp";

    private final Context appContext;
    private final String locale;
    public FileWritingScreenshotCallback(Context appContext, String locale) {
        this.appContext = appContext;
        this.locale = locale;
    }

    @Override
    public void screenshotCaptured(String screenshotName, Bitmap screenshot) {
        try {
            File screenshotDirectory = getFilesDirectory(appContext, locale);
            File screenshotFile = getScreenshotFile(screenshotDirectory, screenshotName);

            OutputStream fos = null;
            try {
                fos = new BufferedOutputStream(new FileOutputStream(screenshotFile));
                screenshot.compress(Bitmap.CompressFormat.PNG, FULL_QUALITY, fos);
            } finally {
                screenshot.recycle();
                if (fos != null) {
                    fos.close();
                }
            }

            Log.d(TAG, "Captured screenshot \"" + screenshotFile.getName() + "\"");
        } catch (Exception e) {
            throw new RuntimeException("Unable to capture screenshot.", e);
        }
    }

    protected File getScreenshotFile(File screenshotDirectory, String screenshotName) {
        String screenshotFileName = screenshotName
                + (shouldAppendTimestamp() ? (NAME_SEPARATOR + System.currentTimeMillis()) : "")
                + EXTENSION;
        return new File(screenshotDirectory, screenshotFileName);
    }

    @SuppressLint("WorldReadableFiles")
    @SuppressWarnings("deprecation")
    private static File getFilesDirectory(Context context, String locale) throws IOException {
        File base;
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.Q) {
            base = context.getDir(SCREENGRAB_DIR_NAME, Context.MODE_PRIVATE);
        } else if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            //noinspection deprecation
            base = context.getDir(SCREENGRAB_DIR_NAME, Context.MODE_WORLD_READABLE);
        } else {
            base = context.getExternalFilesDir(SCREENGRAB_DIR_NAME);
        }
        if (base == null) {
            throw new IOException("Unable to get a world-readable directory");
        }

        File directory = initializeDirectory(new File(new File(base, locale), "/images/screenshots"));
        if (directory == null) {
            throw new IOException("Unable to get a screenshot storage directory");
        }

        Log.d(TAG, "Using screenshot storage directory: " + directory.getAbsolutePath());
        return directory;
    }

    private static File initializeDirectory(File dir) {
        try {
            createPathTo(dir);

            if (dir.isDirectory() && dir.canWrite()) {
                return dir;
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to initialize directory: " + dir.getAbsolutePath(), e);
        }

        return null;
    }

    private static void createPathTo(File dir) throws IOException {
        File parent = dir.getParentFile();
        if (parent != null && !parent.exists()) {
            createPathTo(parent);
        }
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Unable to create output dir: " + dir.getAbsolutePath());
        }
    }

    private static boolean shouldAppendTimestamp() {
        return Boolean.parseBoolean(InstrumentationRegistry.getArguments().getString(APPEND_TIMESTAMP_CONFIG_KEY));
    }
}
