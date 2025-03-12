package com.example.kms.service;

import com.example.kms.model.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptionService {
    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // 비트 단위
    
    public String encrypt(String text, int keyId) throws Exception {
        KeyInfo keyInfo = KeyManager.getKey(keyId);
        if (keyInfo == null) {
            throw new IllegalStateException("키를 찾을 수 없습니다: " + keyId);
        }
        
        SecretKey key = deriveKey(keyInfo.keyMaterial(), keyInfo.salt());
        
        // 랜덤 IV 생성
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        // GCM 파라미터 설정
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        
        byte[] cipherText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        
        // IV와 암호문을 결합
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }
    
    public String decrypt(String encryptedText, int keyId) throws Exception {
        KeyInfo keyInfo = KeyManager.getKey(keyId);
        if (keyInfo == null) {
            throw new IllegalStateException("키를 찾을 수 없습니다: " + keyId);
        }
        
        SecretKey key = deriveKey(keyInfo.keyMaterial(), keyInfo.salt());
        
        // Base64 디코딩
        byte[] cipherMessage = Base64.getDecoder().decode(encryptedText);
        
        // IV 추출
        ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);
        
        // 암호문 추출
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        
        // GCM 파라미터 설정
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        
        byte[] decryptedText = cipher.doFinal(cipherText);
        return new String(decryptedText, StandardCharsets.UTF_8);
    }
    
    private SecretKey deriveKey(String keyMaterial, String salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(
            keyMaterial.toCharArray(),
            hexStringToByteArray(salt),
            100000,
            256
        );
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
    
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
} 