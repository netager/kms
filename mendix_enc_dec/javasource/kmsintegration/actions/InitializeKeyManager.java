package kmsintegration.actions;

import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import java.util.HashMap;
import java.util.Map;
import java.time.LocalDateTime;
import org.apache.commons.lang3.StringUtils;

public class InitializeKeyManager extends CustomJavaAction<Boolean> {
    
    // 메모리에 키를 저장할 정적 맵
    private static final Map<Integer, KeyInfo> keyCache = new HashMap<>();
    
    public InitializeKeyManager(IContext context) {
        super(context);
    }

    @Override
    public Boolean executeAction() throws Exception {
        try {
            // KMS 서버에서 키 가져오기
            KmsClient kmsClient = new KmsClient();
            
            // 설정에서 키 ID 목록 가져오기
            String keyIdsStr = Core.getConfiguration().getConstantValue("KMS.KeyIds");
            String programName = Core.getConfiguration().getConstantValue("KMS.ProgramName");
            
            if (StringUtils.isBlank(keyIdsStr)) {
                throw new RuntimeException("KMS.KeyIds 상수가 설정되지 않았습니다.");
            }
            
            // 쉼표로 구분된 키 ID 목록 처리
            String[] keyIdArray = keyIdsStr.split(",");
            for (String keyIdStr : keyIdArray) {
                int keyId = Integer.parseInt(keyIdStr.trim());
                KeyInfo keyInfo = kmsClient.requestKey(keyId, programName);
                storeKey(keyInfo);
                Core.getLogger("KMS").info("키 ID " + keyId + " 로드 완료");
            }
            
            return true;
        } catch (Exception e) {
            Core.getLogger("KMS").error("키 초기화 실패: " + e.getMessage(), e);
            throw e;
        }
    }
    
    // 키 저장 메서드
    public static void storeKey(KeyInfo keyInfo) {
        keyCache.put(keyInfo.getKeyId(), keyInfo);
    }
    
    // 키 조회 메서드
    public static KeyInfo getKey(int keyId) {
        return keyCache.get(keyId);
    }
    
    // 키 정보 클래스
    public static class KeyInfo {
        private final int keyId;
        private final String keyMaterial;
        private final String salt;
        private final int version;
        private final LocalDateTime lastUpdated;
        
        public KeyInfo(int keyId, String keyMaterial, String salt, int version) {
            this.keyId = keyId;
            this.keyMaterial = keyMaterial;
            this.salt = salt;
            this.version = version;
            this.lastUpdated = LocalDateTime.now();
        }
        
        public int getKeyId() { return keyId; }
        public String getKeyMaterial() { return keyMaterial; }
        public String getSalt() { return salt; }
        public int getVersion() { return version; }
        public LocalDateTime getLastUpdated() { return lastUpdated; }
    }
} 