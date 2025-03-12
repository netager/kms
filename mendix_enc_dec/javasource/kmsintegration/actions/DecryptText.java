package kmsintegration.actions;

import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import com.mendix.core.Core;
import kmsintegration.actions.InitializeKeyManager.KeyInfo;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

public class DecryptText extends CustomJavaAction<String> {
    
    private final String encryptedText;
    private final int keyId;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // 비트 단위
    
    public DecryptText(IContext context, String encryptedText, int keyId) {
        super(context);
        this.encryptedText = encryptedText;
        this.keyId = keyId;
    }

    @Override
    public String executeAction() throws Exception {
        try {
            if (encryptedText == null || encryptedText.isEmpty()) {
                return "";
            }
            
            // 메모리에서 키 정보 가져오기
            KeyInfo keyInfo = InitializeKeyManager.getKey(keyId);
            if (keyInfo == null) {
                throw new IllegalStateException("키를 찾을 수 없습니다: " + keyId);
            }
            
            // 키 유도
            SecretKey key = deriveKey(keyInfo.getKeyMaterial(), keyInfo.getSalt());
            
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
            
            // 복호화 수행
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            
            byte[] decryptedText = cipher.doFinal(cipherText);
            return new String(decryptedText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Core.getLogger("KMS").error("복호화 실패: " + e.getMessage(), e);
            throw e;
        }
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