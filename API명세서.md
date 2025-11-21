# REST API 명세서

## 문서 정보

- **프로젝트명**: 몽음 (Dream Journal & Interpretation Service)
- **작성자**: 오유식
- **작성일**: 2025-11-21
- **버전**: v1.0
- **검토자**: 김민주
- **승인자**: 김민주
- **Base URL**: `http://localhost:8080/api`

---

## 1. API 설계 개요

### 1.1 설계 목적

> 꿈 일기 작성 및 AI 기반 해몽 서비스를 제공하는 RESTful API

### 1.2 설계 원칙

- **RESTful 아키텍처**: HTTP 메서드와 상태 코드의 올바른 사용
- **일관성**: 모든 API 엔드포인트에서 동일한 규칙 적용
- **보안**: JWT 기반 인증 (Bearer Token)
- **문서화**: 명확한 요청/응답 스펙 제공

### 1.3 기술 스택

- **Backend**: Spring Boot 3.5.7 (Java 17)
- **Database**: H2 (local/dev), PostgreSQL (production)
- **인증 방식**: JWT Bearer Token
- **직렬화**: JSON

---

## 2. API 공통 규칙

### 2.1 URL 설계 규칙

| 규칙            | 설명                           | 좋은 예            | 나쁜 예            |
| --------------- | ------------------------------ | ------------------ | ------------------ |
| **명사 사용**   | 동사가 아닌 명사로 리소스 표현 | `/api/dreams`      | `/api/getDreams`   |
| **복수형 사용** | 컬렉션은 복수형으로 표현       | `/api/users`       | `/api/user`        |
| **소문자 사용** | URL은 소문자 사용              | `/api/dreams`      | `/api/Dreams`      |
| **동작 표현**   | HTTP 메서드로 동작 구분        | `POST /api/dreams` | `/api/createDream` |

### 2.2 HTTP 메서드 사용 규칙

| 메서드     | 용도        | 멱등성 | 안전성 | 예시                   |
| ---------- | ----------- | ------ | ------ | ---------------------- |
| **GET**    | 리소스 조회 | ✅     | ✅     | `GET /api/dreams`      |
| **POST**   | 리소스 생성 | ❌     | ❌     | `POST /api/dreams`     |
| **DELETE** | 리소스 삭제 | ✅     | ❌     | `DELETE /api/dreams/1` |

### 2.3 HTTP 상태 코드 가이드

| 코드    | 상태           | 설명               | 사용 예시        |
| ------- | -------------- | ------------------ | ---------------- |
| **200** | OK             | 성공 (데이터 포함) | GET 요청 성공    |
| **201** | Created        | 리소스 생성 성공   | POST 요청 성공   |
| **400** | Bad Request    | 잘못된 요청        | 검증 실패        |
| **401** | Unauthorized   | 인증 필요          | 토큰 없음/만료   |
| **403** | Forbidden      | 권한 없음          | 접근 거부        |
| **404** | Not Found      | 리소스 없음        | 존재하지 않는 ID |
| **409** | Conflict       | 충돌               | 중복 생성 시도   |
| **500** | Internal Error | 서버 오류          | 예기치 못한 오류 |

### 2.4 공통 요청 헤더

```
Content-Type: application/json
Accept: application/json
Authorization: Bearer {JWT_TOKEN}
```

### 2.5 공통 응답 형식

#### 성공 응답 (ApiResponse<T>)

```json
{
  "success": true,
  "message": "Success",
  "data": {
    // 실제 데이터
  }
}
```

**예시 - 회원가입 성공**:

```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "id": 1,
    "nickname": "김철수",
    "email": "chulsoo@example.com",
    "createdAt": "2025-11-21T10:00:00"
  }
}
```

#### 에러 응답 (ErrorResponse)

```json
{
  "timestamp": "2025-11-21T10:30:00",
  "status": 404,
  "error": "D001",
  "message": "Dream not found: ID: 999",
  "path": "/api/dreams/999"
}
```

---

## 3. 인증 및 권한 관리

### 3.1 JWT 토큰 기반 인증

- **액세스 토큰 만료**: 24시간 (86400000ms)
- **토큰 타입**: Bearer
- **토큰 포함 위치**: `Authorization: Bearer {token}`

### 3.2 권한 레벨 정의

| 역할(Role) | 권한      | 설명                                      |
| ---------- | --------- | ----------------------------------------- |
| `USER`     | 기본 권한 | 꿈 등록, 조회, 삭제 (본인 꿈만)           |
| `ADMIN`    | 최고 권한 | 모든 사용자 및 꿈에 대한 접근 가능 (예정) |

### 3.3 공개 엔드포인트

- `POST /api/auth/signup` - 회원가입
- `POST /api/auth/login` - 로그인
- `GET /api/users/{userId}` - 사용자 프로필 조회 (공개)

### 3.4 보호된 엔드포인트

- `GET /api/auth/me` - JWT 필요
- `POST /api/dreams` - JWT 필요
- `GET /api/dreams` - JWT 필요
- `GET /api/dreams/{id}` - JWT 필요 (본인 꿈만)
- `DELETE /api/dreams/{id}` - JWT 필요 (본인 꿈만)

---

## 4. 상세 API 명세

### 4.1 인증 API

#### 4.1.1 회원가입

```yaml
POST /api/auth/signup
Content-Type: application/json
Authorization: 불필요 (공개 API)

Request Body:
{
  "nickname": "김철수",
  "email": "chulsoo@example.com",
  "password": "password123"
}

Validation Rules:
- nickname: 필수, 2~10자
- email: 필수, 2~64자, 유효한 이메일 형식, 중복 불가
- password: 필수, 최소 6자

Response (201 Created):
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "id": 1,
    "nickname": "김철수",
    "email": "chulsoo@example.com",
    "createdAt": "2025-11-21T10:00:00"
  }
}

Response (409 Conflict):
{
  "timestamp": "2025-11-21T10:00:00",
  "status": 409,
  "error": "U002",
  "message": "User already exists with this email: chulsoo@example.com",
  "path": "/api/auth/signup"
}

Response (400 Bad Request):
{
  "success": false,
  "message": "Validation failed: {email=Email should be valid, password=Password must be at least 6 characters}",
  "data": null
}
```

#### 4.1.2 로그인

```yaml
POST /api/auth/login
Content-Type: application/json
Authorization: 불필요 (공개 API)

Request Body:
{
  "email": "chulsoo@example.com",
  "password": "password123"
}

Validation Rules:
- email: 필수, 유효한 이메일 형식
- password: 필수

Response (200 OK):
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaHVsc29vQGV4YW1wbGUuY29tIiwiaWF0IjoxNjk5ODc2NTQzLCJleHAiOjE2OTk5NjI5NDN9.xxxxx",
    "tokenType": "Bearer",
    "expiresIn": 86400000,
    "userId": 1,
    "nickname": "김철수",
    "email": "chulsoo@example.com"
  }
}

Response (401 Unauthorized):
{
  "timestamp": "2025-11-21T10:00:00",
  "status": 401,
  "error": "U003",
  "message": "Invalid email or password",
  "path": "/api/auth/login"
}
```

#### 4.1.3 현재 사용자 정보 조회

```yaml
GET /api/auth/me
Authorization: Bearer {JWT_TOKEN}

Response (200 OK):
{
  "success": true,
  "message": "Success",
  "data": {
    "id": 1,
    "nickname": "김철수",
    "email": "chulsoo@example.com",
    "createdAt": "2025-11-21T10:00:00"
  }
}

Response (401 Unauthorized):
토큰이 없거나 유효하지 않은 경우 403 Forbidden 응답
```

---

### 4.2 꿈 관리 API

#### 4.2.1 꿈 등록

```yaml
POST /api/dreams
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json

Request Body:
{
  "title": "하늘을 나는 꿈",
  "content": "오늘 꿈에서 새처럼 하늘을 자유롭게 날아다녔습니다. 구름 사이를 지나가며 아름다운 풍경을 보았고, 매우 상쾌하고 자유로운 기분이었습니다."
}

Validation Rules:
- title: 필수, 최대 32자
- content: 필수, 최소 10자

Business Rules:
- AI 서버 연동 시 자동으로 다음 정보 생성:
  * interpretation: 해몽 결과
  * emotionCategory: 감정 카테고리 (HAPPY, SAD, ANXIOUS, PEACEFUL, EXCITED, NOSTALGIC, FEARFUL)
  * emotionalAnalysis: 감정 분석 설명
  * recommendedSongName: 추천 곡명
  * recommendedArtist: 추천 아티스트
  * recommendedSongUrl: 추천 곡 URL
- 현재는 임시 데이터로 응답

Response (201 Created):
{
  "success": true,
  "message": "Dream created successfully",
  "data": {
    "id": 1,
    "title": "하늘을 나는 꿈",
    "content": "오늘 꿈에서 새처럼 하늘을 자유롭게 날아다녔습니다. 구름 사이를 지나가며 아름다운 풍경을 보았고, 매우 상쾌하고 자유로운 기분이었습니다.",
    "interpretation": "해몽 결과: 이 꿈은 AI 해몽 서버와 연동되면 자동으로 분석됩니다. 현재는 임시 해몽 메시지가 표시됩니다. 꿈의 내용을 바탕으로 AI가 상징적 의미와 심리적 해석을 제공할 예정입니다.",
    "emotionCategory": "PEACEFUL",
    "emotionalAnalysis": "감정 분석 결과: 이 꿈은 '평온'한 감정을 나타냅니다. AI 서버와 연동되면 더 상세한 감정 분석이 제공됩니다. 꿈의 내용과 맥락을 바탕으로 감정의 원인과 의미를 분석할 예정입니다.",
    "recommendedSongName": "Moonlight Sonata",
    "recommendedArtist": "Ludwig van Beethoven",
    "recommendedSongUrl": "https://www.youtube.com/watch?v=4Tr0otuiQuU",
    "createdAt": "2025-11-21T10:30:00",
    "updatedAt": "2025-11-21T10:30:00"
  }
}

Response (400 Bad Request):
{
  "success": false,
  "message": "Validation failed: {title=Title is required}",
  "data": null
}
```

#### 4.2.2 내 꿈 목록 조회

```yaml
GET /api/dreams
Authorization: Bearer {JWT_TOKEN}

Business Rules:
- 최신순으로 정렬 (createdAt DESC)
- 본인이 작성한 꿈만 조회 가능

Response (200 OK):
{
  "success": true,
  "message": "Success",
  "data": [
    {
      "id": 2,
      "title": "옛 친구를 만나는 꿈",
      "content": "오랜만에 초등학교 친구를 만났습니다. 함께 웃으며 이야기를 나누고 즐거운 시간을 보냈습니다.",
      "interpretation": "해몽 결과: 이 꿈은 AI 해몽 서버와 연동되면 자동으로 분석됩니다...",
      "emotionCategory": "PEACEFUL",
      "emotionalAnalysis": "감정 분석 결과: 이 꿈은 '평온'한 감정을 나타냅니다...",
      "recommendedSongName": "Moonlight Sonata",
      "recommendedArtist": "Ludwig van Beethoven",
      "recommendedSongUrl": "https://www.youtube.com/watch?v=4Tr0otuiQuU",
      "createdAt": "2025-11-21T11:00:00",
      "updatedAt": "2025-11-21T11:00:00"
    },
    {
      "id": 1,
      "title": "하늘을 나는 꿈",
      "content": "오늘 꿈에서 새처럼 하늘을 자유롭게 날아다녔습니다...",
      "interpretation": "해몽 결과: 이 꿈은 AI 해몽 서버와 연동되면 자동으로 분석됩니다...",
      "emotionCategory": "PEACEFUL",
      "emotionalAnalysis": "감정 분석 결과: 이 꿈은 '평온'한 감정을 나타냅니다...",
      "recommendedSongName": "Moonlight Sonata",
      "recommendedArtist": "Ludwig van Beethoven",
      "recommendedSongUrl": "https://www.youtube.com/watch?v=4Tr0otuiQuU",
      "createdAt": "2025-11-21T10:30:00",
      "updatedAt": "2025-11-21T10:30:00"
    }
  ]
}
```

#### 4.2.3 꿈 상세 조회

```yaml
GET /api/dreams/{id}
Authorization: Bearer {JWT_TOKEN}

Path Parameters:
- id: integer (required) - 꿈 ID

Business Rules:
- 본인이 작성한 꿈만 조회 가능
- 다른 사용자의 꿈 조회 시 403 에러

Response (200 OK):
{
  "success": true,
  "message": "Success",
  "data": {
    "id": 1,
    "title": "하늘을 나는 꿈",
    "content": "오늘 꿈에서 새처럼 하늘을 자유롭게 날아다녔습니다. 구름 사이를 지나가며 아름다운 풍경을 보았고, 매우 상쾌하고 자유로운 기분이었습니다.",
    "interpretation": "해몽 결과: 이 꿈은 AI 해몽 서버와 연동되면 자동으로 분석됩니다. 현재는 임시 해몽 메시지가 표시됩니다. 꿈의 내용을 바탕으로 AI가 상징적 의미와 심리적 해석을 제공할 예정입니다.",
    "emotionCategory": "PEACEFUL",
    "emotionalAnalysis": "감정 분석 결과: 이 꿈은 '평온'한 감정을 나타냅니다. AI 서버와 연동되면 더 상세한 감정 분석이 제공됩니다. 꿈의 내용과 맥락을 바탕으로 감정의 원인과 의미를 분석할 예정입니다.",
    "recommendedSongName": "Moonlight Sonata",
    "recommendedArtist": "Ludwig van Beethoven",
    "recommendedSongUrl": "https://www.youtube.com/watch?v=4Tr0otuiQuU",
    "createdAt": "2025-11-21T10:30:00",
    "updatedAt": "2025-11-21T10:30:00",
    "user": {
      "id": 1,
      "nickname": "김철수",
      "email": "chulsoo@example.com",
      "createdAt": "2025-11-21T10:00:00"
    }
  }
}

Response (404 Not Found):
{
  "timestamp": "2025-11-21T10:30:00",
  "status": 404,
  "error": "D001",
  "message": "Dream not found: ID: 999",
  "path": "/api/dreams/999"
}

Response (403 Forbidden):
{
  "timestamp": "2025-11-21T10:30:00",
  "status": 403,
  "error": "D002",
  "message": "Access denied to this dream: Dream ID: 2",
  "path": "/api/dreams/2"
}
```

#### 4.2.4 꿈 삭제

```yaml
DELETE /api/dreams/{id}
Authorization: Bearer {JWT_TOKEN}

Path Parameters:
- id: integer (required) - 꿈 ID

Business Rules:
- 본인이 작성한 꿈만 삭제 가능
- 다른 사용자의 꿈 삭제 시 403 에러

Response (200 OK):
{
  "success": true,
  "message": "Dream deleted successfully",
  "data": null
}

Response (404 Not Found):
{
  "timestamp": "2025-11-21T10:30:00",
  "status": 404,
  "error": "D001",
  "message": "Dream not found: ID: 999",
  "path": "/api/dreams/999"
}

Response (403 Forbidden):
{
  "timestamp": "2025-11-21T10:30:00",
  "status": 403,
  "error": "D002",
  "message": "Access denied to this dream: Dream ID: 2",
  "path": "/api/dreams/2"
}
```

---

### 4.3 사용자 API

#### 4.3.1 사용자 상세 정보 조회

```yaml
GET /api/users/{userId}
Authorization: 불필요 (공개 API)

Path Parameters:
- userId: integer (required) - 사용자 ID

Business Rules:
- 사용자 기본 정보와 해당 사용자가 작성한 모든 꿈 목록 반환
- 꿈 목록은 최신순으로 정렬

Response (200 OK):
{
  "success": true,
  "message": "Success",
  "data": {
    "id": 1,
    "nickname": "김철수",
    "email": "chulsoo@example.com",
    "createdAt": "2025-11-21T10:00:00",
    "dreams": [
      {
        "id": 2,
        "title": "옛 친구를 만나는 꿈",
        "content": "오랜만에 초등학교 친구를 만났습니다...",
        "interpretation": "해몽 결과: 이 꿈은 AI 해몽 서버와...",
        "emotionCategory": "PEACEFUL",
        "emotionalAnalysis": "감정 분석 결과: 이 꿈은 '평온'한 감정을 나타냅니다...",
        "recommendedSongName": "Moonlight Sonata",
        "recommendedArtist": "Ludwig van Beethoven",
        "recommendedSongUrl": "https://www.youtube.com/watch?v=4Tr0otuiQuU",
        "createdAt": "2025-11-21T11:00:00",
        "updatedAt": "2025-11-21T11:00:00"
      },
      {
        "id": 1,
        "title": "하늘을 나는 꿈",
        "content": "오늘 꿈에서 새처럼 하늘을 자유롭게 날아다녔습니다...",
        "interpretation": "해몽 결과: 이 꿈은 AI 해몽 서버와...",
        "emotionCategory": "PEACEFUL",
        "emotionalAnalysis": "감정 분석 결과: 이 꿈은 '평온'한 감정을 나타냅니다...",
        "recommendedSongName": "Moonlight Sonata",
        "recommendedArtist": "Ludwig van Beethoven",
        "recommendedSongUrl": "https://www.youtube.com/watch?v=4Tr0otuiQuU",
        "createdAt": "2025-11-21T10:30:00",
        "updatedAt": "2025-11-21T10:30:00"
      }
    ]
  }
}

Response (404 Not Found):
{
  "timestamp": "2025-11-21T10:30:00",
  "status": 404,
  "error": "U001",
  "message": "User not found: ID: 999",
  "path": "/api/users/999"
}
```

---

## 5. 에러 코드 및 처리

### 5.1 표준 에러 코드 정의

| 코드                    | HTTP 상태 | 설명               | 해결 방법                  |
| ----------------------- | --------- | ------------------ | -------------------------- |
| **VALIDATION_ERROR**    | 400       | 입력값 검증 실패   | 요청 데이터 확인 후 재시도 |
| **INVALID_CREDENTIALS** | 401       | 인증 정보 오류     | 로그인 정보 확인           |
| **INVALID_TOKEN**       | 401       | 토큰 유효하지 않음 | 재로그인                   |
| **ACCESS_DENIED**       | 403       | 권한 없음          | 권한 확인                  |
| **RESOURCE_NOT_FOUND**  | 404       | 리소스 없음        | 요청 URL 및 ID 확인        |
| **DUPLICATE_RESOURCE**  | 409       | 중복 생성 시도     | 기존 리소스 확인           |
| **INTERNAL_ERROR**      | 500       | 서버 내부 오류     | 관리자 문의                |

### 5.2 비즈니스 로직 에러 코드

| 코드                             | HTTP 상태 | 설명                      | 사용 예시                       |
| -------------------------------- | --------- | ------------------------- | ------------------------------- |
| **U001 (USER_NOT_FOUND)**        | 404       | 사용자를 찾을 수 없음     | 존재하지 않는 사용자 ID 조회    |
| **U002 (USER_ALREADY_EXISTS)**   | 409       | 이미 존재하는 이메일      | 중복 이메일로 회원가입 시도     |
| **U003 (INVALID_CREDENTIALS)**   | 401       | 이메일 또는 비밀번호 오류 | 잘못된 로그인 정보              |
| **D001 (DREAM_NOT_FOUND)**       | 404       | 꿈을 찾을 수 없음         | 존재하지 않는 꿈 ID 조회        |
| **D002 (DREAM_ACCESS_DENIED)**   | 403       | 꿈 접근 권한 없음         | 다른 사용자의 꿈 조회/삭제 시도 |
| **A001 (UNAUTHORIZED)**          | 401       | 인증 필요                 | JWT 토큰 없이 보호된 API 접근   |
| **A002 (INVALID_TOKEN)**         | 401       | 토큰이 유효하지 않음      | 만료되었거나 잘못된 JWT 토큰    |
| **V001 (INVALID_INPUT)**         | 400       | 입력값이 유효하지 않음    | 검증 규칙 위반                  |
| **S001 (INTERNAL_SERVER_ERROR)** | 500       | 서버 내부 오류            | 예기치 못한 서버 에러           |

---

## 6. 데이터 모델

### 6.1 감정 카테고리 (EmotionCategory)

| 값          | 한글명 | 설명                        |
| ----------- | ------ | --------------------------- |
| `HAPPY`     | 행복   | 기쁘고 즐거운 감정          |
| `SAD`       | 슬픔   | 슬프고 우울한 감정          |
| `ANXIOUS`   | 불안   | 불안하고 걱정스러운 감정    |
| `PEACEFUL`  | 평온   | 평화롭고 안정적인 감정      |
| `EXCITED`   | 흥분   | 흥분되고 자극적인 감정      |
| `NOSTALGIC` | 그리움 | 그리움과 향수를 느끼는 감정 |
| `FEARFUL`   | 공포   | 두렵고 무서운 감정          |

### 6.2 사용자 역할 (Role)

| 값      | 설명                                      |
| ------- | ----------------------------------------- |
| `USER`  | 일반 사용자 (기본값, 본인 꿈만 관리 가능) |
| `ADMIN` | 관리자 (모든 리소스 접근 가능, 향후 구현) |

---

## 7. 보안

### 7.1 JWT 토큰 구조

```yaml
Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "sub": "user@example.com",
  "iat": 1700000000,
  "exp": 1700086400
}

Security Settings:
- 액세스 토큰 만료: 24시간 (86400000ms)
- Secret Key: application.yaml에서 설정 (운영 환경에서 변경 필수)
- Algorithm: HS256
```

### 7.2 인증 흐름

1. 사용자가 `/api/auth/login`으로 로그인
2. 서버가 JWT 토큰 발급
3. 클라이언트는 토큰을 저장 (LocalStorage, SessionStorage 등)
4. 이후 모든 보호된 API 요청 시 `Authorization: Bearer {token}` 헤더 포함
5. 서버는 JwtAuthenticationFilter에서 토큰 검증
6. 유효한 토큰이면 SecurityContext에 사용자 정보 저장
7. 컨트롤러에서 `@AuthenticationPrincipal User user`로 사용자 정보 접근

### 7.3 보안 설정

- **CSRF**: Disabled (JWT 사용으로 불필요)
- **Session**: Stateless (SessionCreationPolicy.STATELESS)
- **Password Encryption**: BCrypt
- **CORS**: WebConfig에서 설정

---

## 8. 향후 기능

### 8.1 계획된 기능

- **AI 서버 연동**: 실시간 꿈 해몽 및 감정 분석
- **음악 추천 고도화**: 감정별 맞춤 음악 추천
- **감정 카테고리별 필터링**: 특정 감정의 꿈만 조회
- **통계 API**: 사용자별 감정 통계, 월별 꿈 통계
- **검색 기능**: 키워드 기반 꿈 검색
- **공유 기능**: 꿈 공유 및 댓글

### 8.2 API 확장 계획

- `GET /api/dreams/statistics` - 내 꿈 통계
- `GET /api/dreams/search?keyword={keyword}` - 꿈 검색
- `GET /api/dreams/filter?emotion={category}` - 감정별 필터링
- `PATCH /api/dreams/{id}` - 꿈 수정

---

## 9. 테스트 가이드

**주요 테스트 시나리오**:

1. 회원가입 → 로그인 → JWT 토큰 획득
2. 꿈 등록 (3개 이상)
3. 내 꿈 목록 조회
4. 특정 꿈 상세 조회
5. 꿈 삭제
6. 다른 사용자의 꿈 접근 시도 (403 에러 확인)

---

## 10. 참고 문서

- **README.md**: 프로젝트 개요

---

**문서 버전**: v1.0
**최종 수정일**: 2025-11-21
