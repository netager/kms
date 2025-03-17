package com.example.kms.service;

import com.example.kms.config.KmsConfig;
import com.example.kms.model.KeyInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

public class KmsClient {
    private static final Logger logger = LoggerFactory.getLogger(KmsClient.class);
    private final OkHttpClient client;
    private final ObjectMapper objectMapper;
    private final String serverUrl;
    private final String apiToken;
    
    public KmsClient() {
        this.client = new OkHttpClient();
        this.objectMapper = new ObjectMapper();
        this.serverUrl = KmsConfig.getServerUrl();
        this.apiToken = KmsConfig.getApiToken();
    }
    
    public KeyInfo requestKey(int keyId, String programName) throws IOException {
        HttpUrl url = HttpUrl.parse(serverUrl + "/api/v1/key");
        
        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(Map.of(
                "key_id", keyId,
                "program_name", programName
            )),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(url)
            .addHeader("X-API-Token", apiToken)
            .post(body)
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("키 요청 실패: " + response.code());
            }
            
            JsonNode node = objectMapper.readTree(response.body().string());
            
            return new KeyInfo(
                keyId,
                node.get("key_material").asText(),
                node.get("salt").asText(),
                node.get("key_version").asInt(),
                LocalDateTime.now()
            );
        }
    }
} 