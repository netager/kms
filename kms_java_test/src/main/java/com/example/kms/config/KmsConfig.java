package com.example.kms.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class KmsConfig {
    private static final Properties properties = new Properties();
    
    static {
        try (InputStream input = KmsConfig.class.getClassLoader()
                .getResourceAsStream("application.properties")) {
            properties.load(input);
        } catch (IOException e) {
            throw new RuntimeException("설정 파일 로드 실패", e);
        }
    }
    
    public static String getServerUrl() {
        return System.getenv("KMS_SERVER_URL") != null ?
               System.getenv("KMS_SERVER_URL") :
               properties.getProperty("kms.server.url");
    }
    
    public static String getApiToken() {
        String token = System.getenv("KMS_API_TOKEN");
        if (token == null) {
            token = properties.getProperty("kms.api.token");
        }
        if (token == null) {
            throw new RuntimeException("API 토큰이 설정되지 않았습니다.");
        }
        return token;
    }
} 