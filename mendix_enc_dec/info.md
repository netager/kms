# Mendix 암호화/복호화 모듈 구현 가이드

이 문서는 Mendix 애플리케이션에서 KMS(Key Management Service)에서 키를 가져와 메모리에 저장하고, 이를 사용하여 자체적으로 암호화 및 복호화를 수행하는 방법을 설명합니다.

## 1. 개요

이 구현은 다음과 같은 흐름으로 동작합니다:

1. 앱 시작 시 KMS 서버에서 암호화 키를 요청하여 메모리에 저장
2. 암호화 필요 시 메모리에 저장된 키를 사용하여 자체적으로 암호화 수행
3. 복호화 필요 시 메모리에 저장된 키를 사용하여 자체적으로 복호화 수행

## 2. 구성 요소

### 2.1 Java 액션

- **InitializeKeyManager**: 앱 시작 시 KMS에서 키를 가져와 메모리에 저장
- **KmsClient**: KMS 서버와 통신하여 키를 요청
- **EncryptText**: 메모리에 저장된 키를 사용하여 텍스트 암호화
- **DecryptText**: 메모리에 저장된 키를 사용하여 텍스트 복호화

### 2.2 마이크로플로우

- **ACT_InitializeKMS**: 앱 시작 시 키 초기화
- **ACT_EncryptText**: 텍스트 암호화
- **ACT_DecryptText**: 텍스트 복호화

### 2.3 상수

- **KMS.ServerUrl**: KMS 서버 URL
- **KMS.ApiToken**: KMS API 토큰
- **KMS.KeyIds**: 사용할 키 ID 목록 (쉼표로 구분)
- **KMS.ProgramName**: 프로그램 이름

## 3. 설치 및 설정

### 3.1 필요한 의존성

다음 JAR 파일을 Mendix 프로젝트의 `userlib` 폴더에 추가합니다:

- `json-20231013.jar` - JSON 처리용
- `commons-lang3-3.12.0.jar` - 문자열 처리용

### 3.2 Java 액션 추가

`javasource/kmsintegration/actions` 폴더에 다음 Java 클래스를 추가합니다:

- `InitializeKeyManager.java`
- `KmsClient.java`
- `EncryptText.java`
- `DecryptText.java`

### 3.3 상수 설정

Mendix 모듈에 다음 상수를 추가합니다:

1. `KMS.ServerUrl` - KMS 서버 URL (예: http://your-kms-server:8000)
2. `KMS.ApiToken` - KMS API 토큰
3. `KMS.KeyIds` - 사용할 키 ID 목록 (쉼표로 구분, 예: 1,2,3)
4. `KMS.ProgramName` - 프로그램 이름 (예: MendixApp)

### 3.4 앱 시작 시 키 초기화 설정

1. Mendix Modeler에서 새 마이크로플로우 `ACT_InitializeKMS` 생성
2. Java 액션 `InitializeKeyManager` 호출
3. 오류 처리 로직 추가
4. Mendix Modeler에서 `Project` > `Settings` > `Runtime` 메뉴로 이동
5. `After startup` 섹션에서 `ACT_InitializeKMS` 마이크로플로우 선택

## 4. 사용 방법

### 4.1 암호화 마이크로플로우 생성

// 마이크로플로우: ACT_EncryptText
// 파라미터:
// - PlainText (String)
// - KeyId (Integer)
// 반환: String (암호화된 텍스트)

// Java 액션 호출
$encryptedText = javaaction EncryptText($PlainText, $KeyId);
return $encryptedText;

### 4.2 복호화 마이크로플로우 생성

// 마이크로플로우: ACT_DecryptText
// 파라미터:
// - EncryptedText (String)
// - KeyId (Integer)
// 반환: String (복호화된 텍스트)

// Java 액션 호출
$decryptedText = javaaction DecryptText($EncryptedText, $KeyId);
return $decryptedText;

### 4.3 사용 예시

#### 민감한 데이터 암호화

// 마이크로플로우: ACT_SaveCustomerData
// 입력: Customer 엔티티

// 1. 신용카드 번호 암호화
$plainCreditCard = $Customer/creditCardNumber;
$keyId = 1; // 사용할 키 ID
$encryptedCreditCard = ACT_EncryptText($plainCreditCard, $keyId);

// 2. 암호화된 값 저장
$Customer/encryptedCreditCardNumber = $encryptedCreditCard;
$Customer/creditCardNumber = ''; // 평문 삭제
commitObject($Customer);

#### 암호화된 데이터 복호화

// 마이크로플로우: ACT_ViewCustomerData
// 입력: Customer 엔티티
// 출력: String (복호화된 신용카드 번호)

// 1. 암호화된 신용카드 번호 가져오기
$encryptedCreditCard = $Customer/encryptedCreditCardNumber;
$keyId = 1; // 사용할 키 ID

// 2. 복호화
$plainCreditCard = ACT_DecryptText($encryptedCreditCard, $keyId);

// 3. 결과 반환
return $plainCreditCard;

## 5. 보안 고려사항

### 5.1 메모리 보안

- 키 자료는 메모리에만 저장하고 디스크에 저장하지 않음
- 사용하지 않는 키는 메모리에서 제거 (주기적인 가비지 컬렉션)

### 5.2 키 관리

- 정기적인 키 로테이션 계획 수립
- 키 버전 관리 (암호화된 데이터에 키 버전 정보 포함)

### 5.3 오류 처리

- 암호화/복호화 실패 시 적절한 오류 메시지 표시
- 민감한 정보는 로그에 기록하지 않음

### 5.4 접근 제어

- 암호화/복호화 마이크로플로우에 대한 접근 제한
- 암호화된 데이터에 대한 접근 권한 설정

### 5.5 모니터링

- 암호화/복호화 작업 로깅
- 비정상적인 접근 패턴 모니터링

## 6. 성능 최적화

### 6.1 키 유도 결과 캐싱

키 유도 함수(PBKDF2)는 계산 비용이 높으므로, 동일한 키 ID에 대해 반복 계산을 방지하기 위해 키 유도 결과를 캐싱하는 것이 좋습니다.

### 6.2 배치 처리

대량의 데이터를 암호화/복호화할 때는 배치 처리를 구현하여 성능을 향상시킬 수 있습니다.

## 7. 문제 해결

### 7.1 키 초기화 실패

- KMS 서버 연결 확인
- API 토큰 유효성 확인
- 키 ID 존재 여부 확인
- 로그 확인

### 7.2 암호화/복호화 실패

- 키가 메모리에 로드되었는지 확인
- 올바른 키 ID를 사용하는지 확인
- 암호화된 텍스트 형식 확인
- 로그 확인

## 8. 참고 자료

- [Java Cryptography Architecture (JCA)](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [AES-GCM 암호화](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [PBKDF2 키 유도 함수](https://en.wikipedia.org/wiki/PBKDF2)
- [Mendix Java 액션 가이드](https://docs.mendix.com/refguide/java-actions/) 