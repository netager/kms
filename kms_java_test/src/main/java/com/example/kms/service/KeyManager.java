package com.example.kms.service;

import com.example.kms.model.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class KeyManager {
    private static final Logger logger = LoggerFactory.getLogger(KeyManager.class);
    private static final ConcurrentMap<Integer, KeyInfo> keyCache = new ConcurrentHashMap<>();
    
    public static void storeKey(KeyInfo keyInfo) {
        keyCache.put(keyInfo.keyId(), keyInfo);
        logger.info("키가 저장되었습니다. ID: {}, 버전: {}", keyInfo.keyId(), keyInfo.version());
    }
    
    public static KeyInfo getKey(int keyId) {
        KeyInfo keyInfo = keyCache.get(keyId);
        if (keyInfo == null) {
            logger.warn("키를 찾을 수 없습니다. ID: {}", keyId);
        }
        return keyInfo;
    }
    
    public static void clearKeys() {
        keyCache.clear();
        logger.info("모든 키가 제거되었습니다.");
    }
} 