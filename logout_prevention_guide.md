# 로그아웃 문제 방지 가이드

## 구현된 해결책 (2025년 8월 4일)

### 문제 원인
1. Flask-Login의 remember 쿠키가 로그아웃 후에도 남아있음
2. `user_status` 엔드포인트의 세션 복구 로직이 계속 작동
3. `user_loader`가 remember 쿠키를 통해 사용자를 자동 재로그인시킴

### 해결책

#### 1. 로그아웃 플래그 시스템
```python
# 로그아웃 시
flask_session['_logged_out'] = True
flask_session.permanent = False

# user_loader에서 차단
if flask_session.get('_logged_out'):
    return None

# user_status에서 차단
if flask_session.get('_logged_out'):
    return jsonify({"success": False, "message": "로그인이 필요합니다."}), 401
```

#### 2. 강화된 쿠키 삭제
```python
# 모든 관련 쿠키 완전 삭제
response.set_cookie('remember_token', '', expires=0, path='/', domain=None, secure=False, httponly=True)
response.set_cookie('session', '', expires=0, path='/', domain=None, secure=False, httponly=False)

# 추가 쿠키 정리
for cookie_name in ['_user_id', '_fresh', '_id', '_permanent']:
    response.set_cookie(cookie_name, '', expires=0, path='/')
```

#### 3. 로그인 시 플래그 해제
```python
# 모든 로그인 경로에서
flask_session.pop('_logged_out', None)
flask_session.permanent = True
```

### 방어 레이어
1. **user_loader 차단**: remember 쿠키가 있어도 로그아웃한 사용자는 로드 거부
2. **user_status 차단**: 세션 복구 로직 실행 전 로그아웃 플래그 확인
3. **auth_required_with_fallback 차단**: 데코레이터 레벨에서 세션 복구 방지
4. **쿠키 완전 삭제**: 브라우저에서 모든 관련 쿠키 제거
5. **세션 임시화**: 로그아웃 후 세션을 임시로 만들어 브라우저 종료시 자동 삭제

### 테스트 시나리오
1. ✅ 일반 사용자 로그아웃 후 세션 복구 방지
2. ✅ 테스트 계정 로그아웃 후 세션 복구 방지
3. ✅ remember 쿠키 기반 자동 재로그인 방지
4. ✅ JavaScript 로그아웃 버튼 정상 작동
5. ✅ 재로그인 시 로그아웃 플래그 정상 해제

### 향후 방지 조치
1. 로그아웃 기능 수정 시 반드시 이 가이드 참조
2. 새로운 로그인 경로 추가 시 로그아웃 플래그 해제 로직 포함
3. 세션 관련 수정 시 로그아웃 플래그 시스템 고려
4. 정기적인 로그아웃 기능 테스트 수행

### 관련 파일
- `app.py`: 로그아웃 라우트, user_loader, user_status, 인증 데코레이터
- `static/js/script.js`: 프론트엔드 로그아웃 핸들러
- `templates/base.html`: 로그아웃 버튼 UI