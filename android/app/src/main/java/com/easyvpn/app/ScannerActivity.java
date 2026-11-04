package com.easyvpn.app;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ImageFormat;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.graphics.drawable.GradientDrawable;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.util.Size;
import android.view.Gravity;
import android.view.Surface;
import android.view.TextureView;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.TextView;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

/** Camera2 scanner with a single, throttled luminance decoder on a worker thread. */
public final class ScannerActivity extends Activity {
    private static final int CAMERA_PERMISSION_REQUEST = 10;

    private final Object cameraLock = new Object();
    private final AtomicBoolean delivered = new AtomicBoolean(false);
    private final AtomicBoolean decoding = new AtomicBoolean(false);
    private TextureView preview;
    private volatile boolean resumed;
    private HandlerThread cameraThread;
    private Handler cameraHandler;
    private CameraDevice camera;
    private CameraCaptureSession session;
    private ImageReader reader;
    private Surface previewSurface;
    private boolean opening;
    private int generation;
    private long lastDecode;
    private Size previewSize;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
        buildUi();
        if (checkSelfPermission(Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] { Manifest.permission.CAMERA },
                    CAMERA_PERMISSION_REQUEST);
        }
    }

    private int dp(float value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void buildUi() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.rgb(7, 11, 20));
        preview = new TextureView(this);
        root.addView(preview, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        root.addView(new Viewfinder(this), new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));

        TextView hint = new TextView(this);
        hint.setText("Point the camera at a QR code");
        hint.setTextColor(Color.rgb(243, 246, 252));
        hint.setTextSize(17);
        hint.setGravity(Gravity.CENTER);
        hint.setShadowLayer(dp(4), 0, 1, Color.BLACK);
        FrameLayout.LayoutParams hintParams = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, dp(64), Gravity.TOP);
        hintParams.topMargin = dp(48);
        hintParams.leftMargin = dp(20);
        hintParams.rightMargin = dp(20);
        root.addView(hint, hintParams);

        Button cancel = new Button(this);
        cancel.setText("Cancel");
        cancel.setAllCaps(false);
        cancel.setTextColor(Color.WHITE);
        cancel.setTextSize(16);
        GradientDrawable background = new GradientDrawable();
        background.setColor(Color.rgb(26, 34, 54));
        background.setCornerRadius(dp(26));
        background.setStroke(dp(1), Color.rgb(42, 53, 80));
        cancel.setBackground(background);
        FrameLayout.LayoutParams cancelParams = new FrameLayout.LayoutParams(
                dp(180), dp(52), Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        cancelParams.bottomMargin = dp(40);
        root.addView(cancel, cancelParams);
        cancel.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                deliver(1, "cancelled");
            }
        });
        setContentView(root);

        preview.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
            @Override
            public void onSurfaceTextureAvailable(SurfaceTexture texture, int width, int height) {
                openCamera();
            }

            @Override
            public void onSurfaceTextureSizeChanged(SurfaceTexture texture, int width, int height) {
                updatePreviewTransform();
            }

            @Override
            public boolean onSurfaceTextureDestroyed(SurfaceTexture texture) {
                closeCamera();
                return true;
            }

            @Override
            public void onSurfaceTextureUpdated(SurfaceTexture texture) {
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        synchronized (cameraLock) {
            cameraThread = new HandlerThread("easyvpn-qr-camera");
            cameraThread.start();
            cameraHandler = new Handler(cameraThread.getLooper());
        }
        openCamera();
    }

    @Override
    protected void onPause() {
        resumed = false;
        closeCamera();
        HandlerThread thread;
        synchronized (cameraLock) {
            thread = cameraThread;
            cameraThread = null;
            cameraHandler = null;
        }
        if (thread != null) {
            // Do not block the UI waiting for a QR decode already in progress.
            thread.quitSafely();
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        closeCamera();
        if (isFinishing() && delivered.compareAndSet(false, true)) {
            Native.onQrResult(1, "cancelled");
        }
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        deliver(1, "cancelled");
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
                                           int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == CAMERA_PERMISSION_REQUEST) {
            if (grantResults.length == 0
                    || grantResults[0] != PackageManager.PERMISSION_GRANTED) {
                deliver(2, "camera permission denied");
            } else {
                openCamera();
            }
        }
    }

    private void deliver(final int status, final String text) {
        if (!delivered.compareAndSet(false, true)) {
            return;
        }
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (status == 0) {
                    vibrate();
                }
                Native.onQrResult(status, text);
                finish();
            }
        });
    }

    private void vibrate() {
        if (checkSelfPermission(Manifest.permission.VIBRATE)
                != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        try {
            Vibrator vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            if (vibrator != null && vibrator.hasVibrator()) {
                vibrator.vibrate(VibrationEffect.createOneShot(
                        45, VibrationEffect.DEFAULT_AMPLITUDE));
            }
        } catch (RuntimeException ignored) {
            // Feedback is optional and must never lose a successful scan.
        }
    }

    private static Size chooseSize(StreamConfigurationMap map) {
        Size[] yuv = map.getOutputSizes(ImageFormat.YUV_420_888);
        Size[] textures = map.getOutputSizes(SurfaceTexture.class);
        if (yuv == null || textures == null) {
            return null;
        }
        Size best = null;
        double bestScore = Double.MAX_VALUE;
        for (Size candidate : yuv) {
            int w = candidate.getWidth();
            int h = candidate.getHeight();
            if (w > 4096 || h > 4096) {
                continue;
            }
            boolean shared = false;
            for (Size texture : textures) {
                if (candidate.equals(texture)) {
                    shared = true;
                    break;
                }
            }
            if (!shared) {
                continue;
            }
            double aspect = (double) w / h;
            double score = Math.abs(Math.log((double) w * h / (1280.0 * 720.0)))
                    + Math.abs(aspect - 16.0 / 9.0);
            if (score < bestScore) {
                bestScore = score;
                best = candidate;
            }
        }
        return best;
    }

    private void openCamera() {
        if (!resumed || delivered.get() || !preview.isAvailable()
                || checkSelfPermission(Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        synchronized (cameraLock) {
            if (opening || camera != null || cameraHandler == null) {
                return;
            }
            try {
                CameraManager manager = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
                if (manager == null) {
                    deliver(2, "Camera is not available");
                    return;
                }
                String selectedId = null;
                Size selectedSize = null;
                for (String id : manager.getCameraIdList()) {
                    CameraCharacteristics characteristics = manager.getCameraCharacteristics(id);
                    Integer facing = characteristics.get(CameraCharacteristics.LENS_FACING);
                    if (facing == null || facing != CameraCharacteristics.LENS_FACING_BACK) {
                        continue;
                    }
                    StreamConfigurationMap map = characteristics.get(
                            CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
                    Size size = map == null ? null : chooseSize(map);
                    if (size != null) {
                        selectedId = id;
                        selectedSize = size;
                        break;
                    }
                }
                if (selectedId == null) {
                    deliver(2, "No usable back camera was found");
                    return;
                }

                previewSize = selectedSize;
                updatePreviewTransform();
                SurfaceTexture texture = preview.getSurfaceTexture();
                if (texture == null) {
                    return;
                }
                texture.setDefaultBufferSize(selectedSize.getWidth(), selectedSize.getHeight());
                previewSurface = new Surface(texture);
                reader = ImageReader.newInstance(
                        selectedSize.getWidth(), selectedSize.getHeight(),
                        ImageFormat.YUV_420_888, 2);
                final int currentGeneration = ++generation;
                reader.setOnImageAvailableListener(new ImageReader.OnImageAvailableListener() {
                    @Override
                    public void onImageAvailable(ImageReader source) {
                        decodeFrame(source, currentGeneration);
                    }
                }, cameraHandler);
                opening = true;
                manager.openCamera(selectedId, new CameraDevice.StateCallback() {
                    @Override
                    public void onOpened(CameraDevice device) {
                        synchronized (cameraLock) {
                            if (!resumed || delivered.get()
                                    || currentGeneration != generation) {
                                device.close();
                                return;
                            }
                            opening = false;
                            camera = device;
                            createSession(device, currentGeneration);
                        }
                    }

                    @Override
                    public void onDisconnected(CameraDevice device) {
                        cameraFailed(device, currentGeneration, "Camera disconnected");
                    }

                    @Override
                    public void onError(CameraDevice device, int error) {
                        cameraFailed(device, currentGeneration, "Camera error " + error);
                    }
                }, cameraHandler);
            } catch (CameraAccessException | RuntimeException error) {
                closeCamera();
                deliver(2, "Cannot open camera: " + error.toString());
            }
        }
    }

    private void cameraFailed(CameraDevice device, int currentGeneration, String message) {
        synchronized (cameraLock) {
            device.close();
            if (currentGeneration != generation || !resumed || delivered.get()) {
                return;
            }
            closeCamera();
        }
        deliver(2, message);
    }

    private void createSession(final CameraDevice device, final int currentGeneration) {
        try {
            final CaptureRequest.Builder request = device.createCaptureRequest(
                    CameraDevice.TEMPLATE_PREVIEW);
            request.addTarget(previewSurface);
            request.addTarget(reader.getSurface());
            request.set(CaptureRequest.CONTROL_AF_MODE,
                    CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
            request.set(CaptureRequest.CONTROL_AE_MODE, CaptureRequest.CONTROL_AE_MODE_ON);
            device.createCaptureSession(
                    Arrays.asList(previewSurface, reader.getSurface()),
                    new CameraCaptureSession.StateCallback() {
                        @Override
                        public void onConfigured(CameraCaptureSession configured) {
                            synchronized (cameraLock) {
                                if (!resumed || delivered.get()
                                        || currentGeneration != generation || camera != device) {
                                    configured.close();
                                    return;
                                }
                                session = configured;
                                try {
                                    configured.setRepeatingRequest(
                                            request.build(), null, cameraHandler);
                                } catch (CameraAccessException | RuntimeException error) {
                                    closeCamera();
                                    deliver(2, "Cannot start camera preview: " + error.toString());
                                }
                            }
                        }

                        @Override
                        public void onConfigureFailed(CameraCaptureSession failed) {
                            synchronized (cameraLock) {
                                failed.close();
                                if (currentGeneration != generation || !resumed) {
                                    return;
                                }
                                closeCamera();
                            }
                            deliver(2, "Cannot configure camera preview");
                        }
                    }, cameraHandler);
        } catch (CameraAccessException | RuntimeException error) {
            closeCamera();
            deliver(2, "Cannot configure camera: " + error.toString());
        }
    }

    private void decodeFrame(ImageReader source, int currentGeneration) {
        Image image = null;
        boolean ownsDecode = false;
        try {
            synchronized (cameraLock) {
                if (!resumed || currentGeneration != generation || delivered.get()) {
                    return;
                }
                image = source.acquireLatestImage();
            }
            if (image == null) {
                return;
            }
            long now = SystemClock.elapsedRealtime();
            if (now - lastDecode < 250 || !decoding.compareAndSet(false, true)) {
                return;
            }
            ownsDecode = true;
            lastDecode = now;
            Image.Plane plane = image.getPlanes()[0];
            if (plane.getPixelStride() != 1) {
                return;
            }
            int width = image.getWidth();
            int height = image.getHeight();
            int stride = plane.getRowStride();
            long required = (long) (height - 1) * stride + width;
            ByteBuffer buffer = plane.getBuffer();
            if (required <= 0 || required > buffer.remaining()
                    || required > 32L * 1024 * 1024) {
                return;
            }
            byte[] luma = new byte[(int) required];
            buffer.get(luma);
            String result = Native.decodeQr(luma, width, height, stride);
            synchronized (cameraLock) {
                if (result != null && resumed && currentGeneration == generation
                        && !delivered.get()) {
                    deliver(0, result);
                }
            }
        } catch (IllegalStateException ignored) {
            // ImageReader may have been closed by onPause.
        } catch (RuntimeException error) {
            if (resumed && !delivered.get()) {
                deliver(2, "Cannot read camera frame: " + error.toString());
            }
        } finally {
            if (image != null) {
                image.close();
            }
            if (ownsDecode) {
                decoding.set(false);
            }
        }
    }

    private void closeCamera() {
        synchronized (cameraLock) {
            ++generation;
            opening = false;
            if (session != null) {
                session.close();
                session = null;
            }
            if (camera != null) {
                camera.close();
                camera = null;
            }
            if (reader != null) {
                reader.setOnImageAvailableListener(null, null);
                reader.close();
                reader = null;
            }
            if (previewSurface != null) {
                previewSurface.release();
                previewSurface = null;
            }
        }
    }

    private void updatePreviewTransform() {
        if (previewSize == null || preview.getWidth() == 0 || preview.getHeight() == 0) {
            return;
        }
        int rotation = getWindowManager().getDefaultDisplay().getRotation();
        float width = preview.getWidth();
        float height = preview.getHeight();
        float centerX = width / 2;
        float centerY = height / 2;
        RectF view = new RectF(0, 0, width, height);
        RectF buffer = new RectF(0, 0, previewSize.getHeight(), previewSize.getWidth());
        buffer.offset(centerX - buffer.centerX(), centerY - buffer.centerY());
        Matrix matrix = new Matrix();
        if (rotation == Surface.ROTATION_90 || rotation == Surface.ROTATION_270) {
            matrix.setRectToRect(view, buffer, Matrix.ScaleToFit.FILL);
            float scale = Math.max(height / previewSize.getHeight(),
                    width / previewSize.getWidth());
            matrix.postScale(scale, scale, centerX, centerY);
            matrix.postRotate(90 * (rotation - 2), centerX, centerY);
        } else {
            // Portrait back-camera sensors normally have a 90-degree native
            // orientation; TextureView applies that orientation automatically.
            float bufferAspect = (float) previewSize.getHeight() / previewSize.getWidth();
            float viewAspect = width / height;
            if (viewAspect > bufferAspect) {
                matrix.setScale(1, viewAspect / bufferAspect, centerX, centerY);
            } else {
                matrix.setScale(bufferAspect / viewAspect, 1, centerX, centerY);
            }
            if (rotation == Surface.ROTATION_180) {
                matrix.postRotate(180, centerX, centerY);
            }
        }
        preview.setTransform(matrix);
    }

    private final class Viewfinder extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

        Viewfinder(Context context) {
            super(context);
            setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float side = Math.min(getWidth() - dp(48), getHeight() * 0.48f);
            side = Math.max(0, Math.min(side, dp(320)));
            float left = (getWidth() - side) / 2;
            float top = (getHeight() - side) / 2;
            RectF box = new RectF(left, top, left + side, top + side);
            int layer = canvas.saveLayer(0, 0, getWidth(), getHeight(), null);
            paint.setStyle(Paint.Style.FILL);
            paint.setColor(Color.argb(130, 7, 11, 20));
            canvas.drawRect(0, 0, getWidth(), getHeight(), paint);
            paint.setXfermode(new android.graphics.PorterDuffXfermode(
                    android.graphics.PorterDuff.Mode.CLEAR));
            canvas.drawRoundRect(box, dp(24), dp(24), paint);
            paint.setXfermode(null);
            canvas.restoreToCount(layer);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(dp(2));
            paint.setColor(Color.argb(210, 59, 130, 246));
            canvas.drawRoundRect(box, dp(24), dp(24), paint);
        }
    }
}
