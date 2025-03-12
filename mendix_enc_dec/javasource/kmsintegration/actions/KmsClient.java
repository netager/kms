package kmsintegration.actions;

import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.json.JSONObject;
import kmsintegration.actions.InitializeKeyManager.KeyInfo;

public class KmsClient {
    
    private final String serverUrl;
    private final String apiToken;
    
    public KmsClient() {
        // 설정에서 서버 URL과 API 토큰 가져오기
        this.serverUrl = Core.getConfiguration().getConstantValue("KMS.ServerUrl");
        this.apiToken = Core.getConfiguration().getConstantValue("KMS.ApiToken");
        
        if (serverUrl == null || apiToken == null) {
            throw new RuntimeException("KMS 설정이 완료되지 않았습니다. KMS.ServerUrl과 KMS.ApiToken을 확인하세요.");
        }
    }
    
    public KeyInfo requestKey(int keyId, String programName) throws IOException {
        URL url = new URL(serverUrl + "/api/v1/key");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("X-API-Token", apiToken);
        conn.setDoOutput(true);
        
        // 요청 본문 생성
        JSONObject requestBody = new JSONObject();
        requestBody.put("key_id", keyId);
        requestBody.put("program_name", programName);
        
        // 요청 전송
        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = requestBody.toString().getBytes("utf-8");
            os.write(input, 0, input.length);
        }
        
        // 응답 처리
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            throw new IOException("키 요청 실패: HTTP 응답 코드 " + responseCode);
        }
        
        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), "utf-8"))) {
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
        }
        
        // JSON 응답 파싱
        JSONObject jsonResponse = new JSONObject(response.toString());
        
        return new KeyInfo(
            keyId,
            jsonResponse.getString("key_material"),
            jsonResponse.getString("salt"),
            jsonResponse.getInt("key_version")
        );
    }
} 