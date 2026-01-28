# JasoAI - AI 자기소개서 평가 서비스

## Overview
JasoAI is a Flask-based web application that leverages AI to evaluate self-introductions (자기소개서) and provide improvement suggestions. Users can submit their self-introductions via text input or file upload, receiving detailed feedback powered by the OpenAI API. The project aims to offer personalized evaluation tailored to specific companies and job roles, enhancing user's application success.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
- **Template Engine**: Jinja2
- **CSS Framework**: Bootstrap 5.3.0
- **JavaScript**: Vanilla JS for dynamic features
- **Fonts**: Google Fonts (Noto Sans KR)
- **Icons**: Font Awesome 6.4.0
- **Interaction**: Modal-based question detail system for improved user experience.

### Technical Implementations
- **Web Framework**: Flask 3.1.1
- **WSGI Server**: Gunicorn (for production)
- **ORM**: SQLAlchemy with Flask-SQLAlchemy 3.1.1
- **Authentication**: Hybrid system using Flask-Login 0.6.3 and Firebase Authentication for email verification and UID synchronization. Includes automatic account linking and mandatory email verification for Firebase users.
- **Security**: Werkzeug for password hashing, Firebase email verification, reCAPTCHA integration for phone verification.
- **Session Management**: Flask sessions with a secret key, enhanced logout system to prevent session recovery.
- **File Processing**: Support for PDF and DOCX using `pdfplumber` and `python-docx`, with a 5MB size limit.
- **Deployment**: Replit-based development with hot reloading, Gunicorn for production, autoscale deployment, port mapping, and connection pooling.
- **Configuration**: Environment variables for sensitive settings (e.g., API keys, database URL).

### Feature Specifications
- **User Management**: Manages user authentication, authorization, and evaluation credits based on user tiers (e.g., basic_0, basic_1, basic_5). Implements daily usage limits.
- **AI Evaluation Engine**: Integrates OpenAI API for analyzing self-introductions, providing tailored evaluations, scoring, and detailed feedback.
- **Review & Support**: Allows users to write reviews, provides FAQ, and a support system with an admin panel for user management.
- **Payment System**: Integrated PortOne for payment gateway services (KG Inicis, KakaoPay), supporting one-time and multi-use evaluation passes.
- **Account Recovery**: Implements a system for account recovery using PortOne V1 identity verification based on CI hash values.

### System Design Choices
- **Data Flow**: User input -> Preprocessing (text extraction/validation) -> AI Analysis (OpenAI API) -> Result Processing (parsing/DB storage) -> Structured Feedback.
- **Database**: PostgreSQL 16 managed via Nix, with SQLAlchemy for ORM and Flask-SQLAlchemy for migrations.
- **Core Tables**: `users`, `evaluation_records`, `reviews`, `questions` to manage user data, evaluation history, feedback, and support inquiries.
- **Credit Management**: FIFO consumption of evaluation credits with a 3-month expiration policy, tracked via a `CreditPurchase` table.

## External Dependencies

### API Services
- **OpenAI API**: For AI-powered self-introduction analysis and evaluation.
- **Firebase Authentication**: For user authentication and management (email, UID synchronization).
- **PortOne (KG Inicis, KakaoPay)**: Payment gateway integration.

### File Processing Libraries
- **pdfplumber**: For extracting text from PDF files.
- **python-docx**: For processing and extracting text from Word documents.

### Infrastructure
- **PostgreSQL**: Relational database.
- **Gunicorn**: WSGI HTTP server for production deployment.
- **Nix**: Package manager for development environment setup.

## Recent Changes
- October 1, 2025 (Evening Update 3): 계정 복구 로직 완전 수정
  - **세션 키 통일**: `recover_ci_hash`, `recover_phone`, `recover_user_id` 명명 규칙 통일
  - **회원가입 로직 재사용**: CI 해시(SHA-256), 전화번호 정규화(User.normalize_phone) 함수를 가입 로직과 동일하게 사용
  - **Fallback 조회**: ci_hash 우선 조회, 없으면 정규화된 phone으로 fallback 매칭
  - **세션 기반 복구**: finalize(GET)에서 user_id를 세션에 저장, POST에서 재사용하여 안정성 향상
  - **상세 로깅**: [IDV-CB][OK], [RECOVER][OK]/[FAIL] 로그로 각 단계별 성공/실패 추적
  - **수정된 라우트**: idv_recover_callback, account_recover_finalize, account_recover_result, account_reset_password
- October 1, 2025 (Evening Update 2): 계정 복구 매칭 버그 수정 및 관리자 패널 강화
  - **계정 복구 매칭 수정**: ci 컬럼 대신 ci_hash 컬럼으로 올바르게 조회 (account_recover_result, account_reset_password, account_recover_finalize)
  - **복구 로깅 추가**: [RECOVER][OK]/[FAIL] 로그로 계정 매칭 성공/실패 추적
  - **관리자 패널 버튼 강화**: current_user.role과 session['role'] 모두 지원하여 안정적인 버튼 표시
  - **수정된 파일**: app.py (3개 라우트 함수), templates/base.html (관리자 버튼 조건)
- October 1, 2025 (Evening): 관리자 패널 네비게이션 및 IDV 복구 시스템 개선
  - **관리자 패널 버튼**: base.html 헤더에 role=admin 사용자에게만 "관리자 패널" 버튼 표시 (서버 사이드 렌더링)
  - **/admin/dashboard 라우트**: 전용 관리자 대시보드 라우트 복구, /admin은 자동 리다이렉트
  - **관리자 접근 제어**: admin_required 데코레이터에 로깅 추가 ([ADMIN-NAV][OK]/[FAIL])
  - **IDV 복구 V1 SDK 통합**: 회원가입과 동일한 PortOne V1 SDK (IMP.certification) 사용
  - **IDV 복구 백엔드**: _verify_portone_identity 함수로 imp_uid 검증, V2 API 제거
  - **강화된 에러 처리**: IDV 복구에 상세 로깅 ([IDV-RECOVER][OK]/[FAIL]) 및 구체적 에러 코드 반환
  - **환경 변수**: PORTONE_IMP_CODE_LIVE, PORTONE_CHANNEL_KEY, PORTONE_API_KEY, PORTONE_API_SECRET 필요