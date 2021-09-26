package com.example.cyberproject;

import android.graphics.Bitmap;
import android.hardware.camera2.CameraAccessException;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class ImageTaker extends Thread {

    private static final String CYPHER_MODE = "AES/CBC/NoPadding";

    private IvParameterSpec IV;
    private SecretKeySpec SECRET_KEY_SPECS;

    private static final int PORT = 9768;

    private static final long INITIAL_DELAY = 1000;
    private static final long MINIMUM_DELAY = 50;

    private MainActivity activity;
    private InputStream in;
    private OutputStream out;

    public ImageTaker(String ip, MainActivity activity) {
        this.activity = activity;

        try {
            Socket socket = new Socket(ip, PORT);
            in = socket.getInputStream();
            out = socket.getOutputStream();

            //establish connection
            String keySeed = generateRandomSeed();
            String ivSeed = generateRandomSeed();

            System.out.println(keySeed);

            SECRET_KEY_SPECS = new SecretKeySpec(keySeed.getBytes(), "AES");
            IV = new IvParameterSpec(ivSeed.getBytes());

            String publicKey = readStringNoAES();
            RSAPublicKey RSAkey = readPublicKey(publicKey);

            sendNoAES(RSAencrypt(keySeed.getBytes(), RSAkey));
            sendNoAES(RSAencrypt(ivSeed.getBytes(), RSAkey));

            start();
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private String generateRandomSeed() {
        StringBuilder seed = new StringBuilder();

        for (int i = 0; i < 16; i++) {
            seed.append((char) (Math.random() * 26 + 65));
        }
        return seed.toString();
    }

    public static byte[] RSAencrypt(byte[] bArr, PublicKey publicKey) throws Throwable {
        Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        instance.init(1, publicKey);
        return Base64.encodeBase64(instance.doFinal(bArr));
    }

    public static RSAPublicKey readPublicKey(String key) throws Exception {
        byte[] encoded = Base64.decodeBase64(key);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    @Override
    public void run() {
        long startingTime = System.currentTimeMillis();

        while (System.currentTimeMillis() < startingTime + INITIAL_DELAY) ;

        while (true) {
            startingTime = System.currentTimeMillis();
            while (System.currentTimeMillis() < startingTime + MINIMUM_DELAY) ;
            String request = readString();
            if ("TAKE PICTURE".equals(request)) {

                lock();
                Bitmap bmp = activity.textureView.getBitmap();
                unlock();
                if (bmp != null) {
                    Bitmap resized = Bitmap.createScaledBitmap(bmp, 100, 100, true);

                    ByteArrayOutputStream stream = new ByteArrayOutputStream();
                    resized.compress(Bitmap.CompressFormat.JPEG, 100, stream);
                    byte[] byteArray = stream.toByteArray();

                    send(byteArray);
                }
            }
        }
    }

    private void send(byte[] data) {
        try {
            byte[] cypherText = encrypt(data);
            data = Base64.encodeBase64(cypherText);


            byte[] sentData = new byte[4 + data.length];
            ByteBuffer buff = ByteBuffer.wrap(sentData);
            buff.putInt(data.length);
            buff.put(data);

            out.write(buff.array());
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendNoAES(byte[] data) {
        try {
            byte[] sentData = new byte[4 + data.length];
            ByteBuffer buff = ByteBuffer.wrap(sentData);
            buff.putInt(data.length);
            buff.put(data);

            out.write(buff.array());
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] readNoAES() {
        try {
            byte[] read = new byte[4];
            in.read(read);
            byte[] data = new byte[ByteBuffer.wrap(read).getInt()];
            in.read(data);

            return data;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private String readStringNoAES() {
        return new String(readNoAES());
    }

    private byte[] read() {
        try {
            byte[] read = new byte[4];
            in.read(read);
            byte[] data = new byte[ByteBuffer.wrap(read).getInt()];
            in.read(data);

            byte[] deB64 = decrypt(Base64.decodeBase64(data));

            return deB64;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private String readString() {
        return new String(read());
    }

    private void lock() {
        try {
            activity.cameraCaptureSession.capture(activity.captureRequestBuilder.build(),
                    null, activity.backgroundHandler);
        } catch (CameraAccessException e) {
            e.printStackTrace();
        }
    }

    private void unlock() {
        try {
            activity.cameraCaptureSession.setRepeatingRequest(activity.captureRequestBuilder.build(),
                    null, activity.backgroundHandler);
        } catch (CameraAccessException e) {
            e.printStackTrace();
        }
    }

    private byte[] encrypt(byte[] value) {
        try {
            Cipher cipher = Cipher.getInstance(CYPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY_SPECS, IV);
            int blockSize = cipher.getBlockSize();
            byte[] plaintext = padding(value, blockSize);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] decrypt(byte[] encrypted) {
        try {
            Cipher cipher = Cipher.getInstance(CYPHER_MODE);
            cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY_SPECS, IV);

            return unpadding(cipher.doFinal(encrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] padding(byte[] value, int blockSize) {
        int plaintextLength = value.length;
        if (plaintextLength % blockSize != 0) {
            plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
        }
        byte[] plaintext = new byte[plaintextLength];
        System.arraycopy(value, 0, plaintext, 0, value.length);
        return plaintext;
    }

    private static byte[] unpadding(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0) {
            --i;
        }

        return Arrays.copyOf(bytes, i + 1);
    }
}