package com.example.kms;

import com.example.kms.model.KeyInfo;
import com.example.kms.service.EncryptionService;
import com.example.kms.service.KeyManager;
import com.example.kms.service.KmsClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KmsApplication {
    private static final Logger logger = LoggerFactory.getLogger(KmsApplication.class);
    
    public static void main(String[] args) {
        try {
            // KMS 클라이언트 초기화
            KmsClient kmsClient = new KmsClient();
            EncryptionService encryptionService = new EncryptionService();
            
            // 키 요청 및 저장
            int keyId = 1; // 사용할 키 ID
            String programName = "KmsJavaTest";
            
            logger.info("키 요청 중...");
            KeyInfo keyInfo = kmsClient.requestKey(keyId, programName);
            KeyManager.storeKey(keyInfo);
            logger.info("키가 메모리에 저장되었습니다.");
            
            // 암호화 테스트
            String originalText = "Hello, KMS!";
            logger.info("원본 텍스트: {}", originalText);
            
            String encryptedText = encryptionService.encrypt(originalText, keyId);
            logger.info("암호화된 텍스트: {}", encryptedText);
            
            String decryptedText = encryptionService.decrypt(encryptedText, keyId);
            logger.info("복호화된 텍스트: {}", decryptedText);
            
        } catch (Exception e) {
            logger.error("오류 발생: ", e);
            System.exit(1);
        }
    }
} 