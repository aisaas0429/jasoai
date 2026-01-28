from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import event
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates
from datetime import datetime, timedelta, date
import os
import re

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)  # nullable for userID-based signup
    email_lower = db.Column(db.String(120), unique=True, nullable=True, index=True)  # lowercase email for case-insensitive lookup
    username = db.Column(db.String(50), unique=True, nullable=True, index=True)  # username field (formerly user_id)
    firebase_uid = db.Column(db.String(128), unique=True, nullable=True, index=True)  # Firebase UID for email verification
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), unique=True, nullable=True, index=True)  # normalized phone number (010xxxxxxxx format)
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)  # phone verification status
    
    # 사용자 등급 정보
    plan_type = db.Column(db.String(50), default='basic_0회', nullable=False)
    remaining_credits = db.Column(db.Integer, default=0)
    evaluation_ticket = db.Column(db.Integer, default=0, nullable=False)  # 평가권 (정합성 관리용)
    daily_usage_count = db.Column(db.Integer, default=0)
    last_usage_date = db.Column(db.Date, nullable=True)
    
    # 메타 정보
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), default='user', nullable=False, index=True)  # 사용자 역할 (user, admin)
    
    # KG이니시스 본인인증 기능
    realname_verified = db.Column(db.Boolean, default=False)  # 본인인증 완료 여부
    ci_hash = db.Column(db.String(64), unique=True, nullable=True)  # CI 해시값 (유니크)
    verified_at = db.Column(db.DateTime, nullable=True)  # 본인인증 완료 시간
    verified_name = db.Column(db.String(100), nullable=True)  # 본인인증된 실명
    birth = db.Column(db.String(10), nullable=True)  # 본인인증된 생년월일 (YYYY-MM-DD)
    
    # 하위 호환성을 위한 기존 컬럼들 (데이터베이스에 실제 존재)
    user_id = db.Column(db.String(50), unique=True, nullable=True, index=True)  # 기존 user_id 컬럼
    phone_number = db.Column(db.String(20), nullable=True)  # 기존 phone_number 컬럼
    
    # Flask-Login 필수 메서드 구현
    def get_id(self):
        """Flask-Login에서 사용자 식별용 ID 반환"""
        return str(self.id)
    
    @property
    def is_active(self):
        """계정 활성화 상태 반환 (UserMixin 호환)"""
        return self.active
    
    def check_password(self, password):
        """비밀번호 검증"""
        return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        """비밀번호 설정"""
        self.password_hash = generate_password_hash(password)
    
    def update_login_time(self):
        """로그인 시간 업데이트"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    # 하위 호환성을 위한 hybrid property들
    @hybrid_property
    def user_id_compat(self):
        """하위 호환성을 위한 user_id 속성 (username과 동일)"""
        return self.username or self.user_id
    
    @user_id_compat.setter
    def user_id_compat(self, value):
        self.username = value
        if self.user_id != value:
            self.user_id = value
    
    @hybrid_property
    def phone_number_compat(self):
        """하위 호환성을 위한 phone_number 속성 (phone과 동일)"""
        return self.phone or self.phone_number
    
    @phone_number_compat.setter
    def phone_number_compat(self, value):
        normalized = self.normalize_phone(value) if value else None
        self.phone = normalized
        if self.phone_number != normalized:
            self.phone_number = normalized
    
    @staticmethod
    def normalize_phone(phone_str):
        """전화번호를 010xxxxxxxx 형식으로 정규화"""
        if not phone_str:
            return None
        
        # 숫자만 추출
        digits = re.sub(r'\D', '', phone_str)
        
        # 010으로 시작하는 11자리 번호인지 확인
        if len(digits) == 11 and digits.startswith('010'):
            return digits
        
        # 기타 형식들 처리
        if len(digits) == 10 and digits.startswith('10'):
            return '0' + digits
        
        # 원본 반환 (검증은 별도로)
        return phone_str
    
    @validates('email')
    def validate_email(self, key, email):
        """이메일 설정 시 email_lower 자동 설정"""
        if email:
            self.email_lower = email.lower()
        else:
            self.email_lower = None
        return email
    
    @validates('phone')
    def validate_phone(self, key, phone):
        """전화번호 설정 시 자동 정규화"""
        return self.normalize_phone(phone)
    
    @validates('username')
    def validate_username(self, key, username):
        """username 설정 시 user_id도 동기화"""
        if username and self.user_id != username:
            self.user_id = username
        return username
    
    def get_status_info(self):
        """사용자 상태 정보 반환"""
        status_info = {
            'plan': 'Basic',
            'remaining': f'{self.remaining_credits}회 남음',
            'type': 'credits'
        }
        
        # 플랜 타입별 상세 정보
        if 'premium' in self.plan_type.lower():
            status_info['plan'] = 'Premium'
        elif 'pro' in self.plan_type.lower():
            status_info['plan'] = 'Pro'
        
        return status_info
    
    def to_dict(self):
        """사용자 정보를 딕셔너리로 변환"""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'user_id': self.user_id_compat,  # backward compatibility
            'name': self.name,
            'plan_type': self.plan_type,
            'remaining_credits': self.remaining_credits,
            'daily_usage_count': self.daily_usage_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'phone': self.phone,
            'phone_number': self.phone_number_compat,  # backward compatibility
            'phone_verified': self.phone_verified,
            # 'realname_verified': self.realname_verified,  # 향후 추가 예정
            # 'verified_at': self.verified_at.isoformat() if self.verified_at else None  # 향후 추가 예정
        }
    
    def clean_expired_credits(self):
        """만료된 평가권 정리 (3개월 기준)"""
        try:
            # 3개월 전 날짜 계산
            three_months_ago = datetime.now() - timedelta(days=90)
            
            # 해당 사용자의 만료된 구매 기록 조회
            expired_purchases = CreditPurchase.query.filter(
                CreditPurchase.user_id == self.id,
                CreditPurchase.expired_at.is_(None),  # 아직 만료 처리되지 않은 것들
                CreditPurchase.purchase_date <= three_months_ago
            ).all()
            
            expired_count = 0
            for purchase in expired_purchases:
                if purchase.remaining_amount > 0:
                    expired_count += purchase.remaining_amount
                    # 잔여 크레딧을 사용자에서 차감
                    self.remaining_credits = max(0, self.remaining_credits - purchase.remaining_amount)
                    # 만료 처리
                    purchase.remaining_amount = 0
                    purchase.expired_at = datetime.now()
            
            if expired_count > 0:
                db.session.commit()
                
            return expired_count
        except Exception as e:
            db.session.rollback()
            return 0


class CreditPurchase(db.Model):
    """크레딧 구매 기록 테이블 (개별 구매 추적용)"""
    __tablename__ = 'credit_purchases'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    original_amount = db.Column(db.Integer, nullable=False)  # 원래 구매한 평가권 수
    remaining_amount = db.Column(db.Integer, nullable=False)  # 남은 평가권 수
    expires_at = db.Column(db.DateTime, nullable=False)  # 만료 예정일 (구매일 + 90일)
    expired_at = db.Column(db.DateTime, nullable=True)  # 실제 만료 처리일
    imp_uid = db.Column(db.String(100), nullable=True)  # 포트원 거래 고유번호
    merchant_uid = db.Column(db.String(100), nullable=True)  # 주문번호
    product_name = db.Column(db.String(100), nullable=True)  # 상품명
    amount = db.Column(db.Integer, nullable=True)  # 결제 금액
    refund_status = db.Column(db.String(20), default='none', nullable=False)  # none, requested, approved, rejected
    refund_requested_at = db.Column(db.DateTime, nullable=True)  # 환불 요청일
    
    # 추가 필드 (관리자 패널용)
    product_code = db.Column(db.String(50), nullable=True, index=True)  # EVAL_1, EVAL_5
    credits_added = db.Column(db.Integer, nullable=True)  # 추가된 평가권 수 (original_amount와 동일)
    status = db.Column(db.String(20), nullable=True, index=True)  # paid, refund_requested, refunded
    paid_at = db.Column(db.DateTime, nullable=True, index=True)  # 결제 완료 시각 (purchase_date와 동일)
    refunded_at = db.Column(db.DateTime, nullable=True)  # 환불 완료 시각
    credited_at = db.Column(db.DateTime, nullable=True)  # 크레딧 지급 완료 시각 (정합성 체크용)
    refund_id = db.Column(db.String(100), nullable=True)  # 환불 거래 ID
    refund_amount = db.Column(db.Integer, nullable=True)  # 환불 금액
    
    # 관계 설정
    user = db.relationship('User', backref=db.backref('credit_purchases', lazy=True))
    
    @property
    def is_expired(self):
        """만료 여부 확인"""
        return datetime.utcnow() > self.expires_at
    
    @property 
    def days_until_expiry(self):
        """만료까지 남은 일수"""
        if self.is_expired:
            return 0
        delta = self.expires_at - datetime.utcnow()
        return delta.days
    
    def __repr__(self):
        return f'<CreditPurchase {self.user_id}: {self.remaining_amount}/{self.original_amount}>'


class EvaluationRecord(db.Model):
    """자기소개서 평가 기록"""
    __tablename__ = 'evaluation_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    evaluation_type = db.Column(db.String(50), nullable=True)  # 실제 DB 컬럼
    source_title = db.Column(db.String(200), nullable=True)  # 실제 DB 컬럼 (회사명/직무명)
    evaluation_result = db.Column(db.Text, nullable=True)
    grade = db.Column(db.String(10), nullable=True)  # 실제 DB 컬럼
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payment_type = db.Column(db.String(50), nullable=True)  # 실제 DB 컬럼
    result_id = db.Column(db.String(100), nullable=True)  # 실제 DB 컬럼
    
    # 관계 설정
    user = db.relationship('User', backref=db.backref('evaluations', lazy=True))
    
    # 하위 호환성을 위한 프로퍼티들
    @property
    def company_name(self):
        return self.source_title
    
    @property
    def job_position(self):
        return self.evaluation_type
    
    @property
    def content(self):
        # content 정보는 evaluation_result에 포함되어 있을 수 있음
        return self.evaluation_result or "평가 내용"
    
    def __repr__(self):
        return f'<EvaluationRecord {self.id}: {self.source_title}>'


class Review(db.Model):
    """사용자 후기"""
    __tablename__ = 'reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # 비회원도 작성 가능
    writer_name = db.Column(db.String(100), nullable=False)  # 실제 DB 컬럼명과 일치
    title = db.Column(db.String(200), nullable=True)  # 실제 DB에 존재하는 컬럼
    content = db.Column(db.Text, nullable=False)
    stars = db.Column(db.Integer, nullable=False)  # 실제 DB 컬럼명과 일치 (1-5 별점)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 관계 설정
    user = db.relationship('User', backref=db.backref('reviews', lazy=True))
    
    # 하위 호환성을 위한 프로퍼티
    @property
    def name(self):
        return self.writer_name
    
    @property  
    def rating(self):
        return self.stars
    
    def __repr__(self):
        return f'<Review {self.id}: {self.writer_name} - {self.stars}★>'


class Question(db.Model):
    """문의사항"""
    __tablename__ = 'questions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # 비회원도 문의 가능
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    answered = db.Column(db.Boolean, default=False)  # 실제 DB 컬럼명과 일치
    answer_content = db.Column(db.Text, nullable=True)  # 실제 DB 컬럼명과 일치
    answered_at = db.Column(db.DateTime, nullable=True)
    answered_by = db.Column(db.Integer, nullable=True)  # 실제 DB에 존재하는 컬럼
    is_active = db.Column(db.Boolean, default=True)  # 실제 DB에 존재하는 컬럼
    is_private = db.Column(db.Boolean, default=False)  # 실제 DB에 존재하는 컬럼
    
    # 관계 설정
    user = db.relationship('User', backref=db.backref('questions', lazy=True))
    
    # 하위 호환성을 위한 프로퍼티들
    @property
    def is_answered(self):
        return self.answered
    
    @property
    def answer(self):
        return self.answer_content
    
    def get_status(self):
        """문의 상태 반환 (기본값: received)"""
        if self.answered:
            return 'answered'
        return 'received'
    
    def get_masked_author(self, current_user=None):
        """작성자 정보 마스킹 처리"""
        if self.user:
            # 본인이거나 관리자인 경우 전체 표시
            if current_user and hasattr(current_user, 'id'):
                if current_user.id == self.user_id:
                    return self.user.username or self.user.email or '익명'
                if hasattr(current_user, 'role') and current_user.role == 'admin':
                    return self.user.username or self.user.email or '익명'
            # 그 외에는 마스킹
            username = self.user.username or self.user.email or '익명'
            if len(username) > 3:
                return username[:2] + '*' * (len(username) - 2)
            return username[0] + '*' * (len(username) - 1)
        return '익명'
    
    def to_dict(self, current_user=None):
        """JSON 직렬화를 위한 딕셔너리 변환"""
        # JasoAI: status 기본값 추가 및 필드 안전성 보장
        return {
            'id': self.id,
            'title': self.title or '',
            'content': self.content or '',
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'answered': self.answered if self.answered is not None else False,
            'answer_content': self.answer_content or '',
            'answered_at': self.answered_at.isoformat() if self.answered_at else None,
            'is_private': self.is_private if self.is_private is not None else False,
            'user_id': self.user_id,
            'status': self.get_status(),
            'author': self.get_masked_author(current_user)
        }
    
    def __repr__(self):
        return f'<Question {self.id}: {self.title}>'


class Notification(db.Model):
    """인앱 알림 (결제/환불 등)"""
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    type = db.Column(db.String(50), nullable=False)  # payment_success, refund_requested, refund_approved
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    meta_json = db.Column(db.Text, nullable=True)  # JSON 형태의 메타 데이터
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    read_at = db.Column(db.DateTime, nullable=True)
    
    # 관계 설정
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    
    @property
    def is_read(self):
        """읽음 여부"""
        return self.read_at is not None
    
    def mark_as_read(self):
        """읽음 처리"""
        if not self.read_at:
            self.read_at = datetime.utcnow()
    
    def to_dict(self):
        """JSON 직렬화"""
        return {
            'id': self.id,
            'type': self.type,
            'title': self.title,
            'body': self.body,
            'meta': self.meta_json,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'is_read': self.is_read
        }
    
    def __repr__(self):
        return f'<Notification {self.id}: {self.type} to user {self.user_id}>'


class CreditsLedger(db.Model):
    """크레딧 증감 이력 (정합성 보증용 불변 장부)"""
    __tablename__ = 'credits_ledger'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('credit_purchases.id'), nullable=True, index=True)
    delta = db.Column(db.Integer, nullable=False)  # +1, +5, -1, -5 등
    reason = db.Column(db.String(50), nullable=False)  # 'payment', 'refund', 'manual', 'reconcile'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    note = db.Column(db.Text, nullable=True)  # 추가 설명
    
    # 관계 설정
    user = db.relationship('User', backref=db.backref('credits_ledger', lazy=True))
    payment = db.relationship('CreditPurchase', backref=db.backref('ledger_entries', lazy=True))
    
    def __repr__(self):
        return f'<CreditsLedger user={self.user_id} delta={self.delta} reason={self.reason}>'