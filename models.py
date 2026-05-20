"""
models.py — SQLAlchemy ORM models replacing flat JSON file storage.
Provides: User, Analysis, APIKey, Webhook
"""
from datetime import datetime, timezone
import uuid
import secrets
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def _utcnow():
    return datetime.now(timezone.utc)


def _new_uuid():
    return str(uuid.uuid4())


def _new_token(n=32):
    return secrets.token_urlsafe(n)


# ─────────────────────────────────────────────────────────────
#  User
# ─────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = 'users'

    id         = db.Column(db.String(36), primary_key=True, default=_new_uuid)
    username   = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email      = db.Column(db.String(120), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    role       = db.Column(db.String(20), default='user', nullable=False)  # user | admin
    is_active  = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    analyses = db.relationship('Analysis', back_populates='user',
                               cascade='all, delete-orphan', lazy='dynamic')
    api_keys = db.relationship('APIKey', back_populates='user',
                               cascade='all, delete-orphan', lazy='dynamic')
    webhooks = db.relationship('Webhook', back_populates='user',
                               cascade='all, delete-orphan', lazy='dynamic')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self, public=True):
        d = {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }
        if not public:
            d['email'] = self.email
            d['is_active'] = self.is_active
        return d


# ─────────────────────────────────────────────────────────────
#  Analysis
# ─────────────────────────────────────────────────────────────
class Analysis(db.Model):
    __tablename__ = 'analyses'

    id             = db.Column(db.String(36), primary_key=True, default=_new_uuid)
    user_id        = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    url            = db.Column(db.String(2048), nullable=False, index=True)

    # Status: pending | running | done | failed
    status         = db.Column(db.String(20), default='done', nullable=False, index=True)
    job_id         = db.Column(db.String(64), nullable=True)   # RQ job id

    # Scores (denormalised for fast list queries)
    overall_score  = db.Column(db.Float, nullable=True)
    security_score = db.Column(db.Float, nullable=True)
    seo_score      = db.Column(db.Float, nullable=True)
    perf_score     = db.Column(db.Float, nullable=True)
    html_score     = db.Column(db.Float, nullable=True)
    css_score      = db.Column(db.Float, nullable=True)
    js_score       = db.Column(db.Float, nullable=True)
    a11y_score     = db.Column(db.Float, nullable=True)

    issues_high    = db.Column(db.Integer, default=0)
    issues_medium  = db.Column(db.Integer, default=0)
    issues_low     = db.Column(db.Integer, default=0)
    load_time      = db.Column(db.Float, nullable=True)
    html_size_kb   = db.Column(db.Float, nullable=True)

    # Full JSON result blob
    result_json    = db.Column(db.Text, nullable=True)

    cached         = db.Column(db.Boolean, default=False)
    tags           = db.Column(db.String(512), nullable=True)  # comma-separated
    notes          = db.Column(db.Text, nullable=True)

    created_at     = db.Column(db.DateTime(timezone=True), default=_utcnow, index=True)
    updated_at     = db.Column(db.DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    user = db.relationship('User', back_populates='analyses')

    def slim_dict(self):
        return {
            'id':            self.id,
            'url':           self.url,
            'status':        self.status,
            'score':         self.overall_score,
            'security':      self.security_score,
            'performance':   self.perf_score,
            'seo':           self.seo_score,
            'issues_high':   self.issues_high,
            'issues_medium': self.issues_medium,
            'issues_low':    self.issues_low,
            'load_time':     self.load_time,
            'cached':        self.cached,
            'tags':          self.tags.split(',') if self.tags else [],
            'notes':         self.notes,
            'created_at':    self.created_at.isoformat() if self.created_at else None,
        }


# ─────────────────────────────────────────────────────────────
#  API Key
# ─────────────────────────────────────────────────────────────
class APIKey(db.Model):
    __tablename__ = 'api_keys'

    id         = db.Column(db.String(36), primary_key=True, default=_new_uuid)
    user_id    = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    key        = db.Column(db.String(64), unique=True, nullable=False, default=_new_token)
    name       = db.Column(db.String(128), nullable=False, default='Default key')

    is_active  = db.Column(db.Boolean, default=True)
    last_used  = db.Column(db.DateTime(timezone=True), nullable=True)
    uses       = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship('User', back_populates='api_keys')

    def to_dict(self, show_key=False):
        d = {
            'id':         self.id,
            'name':       self.name,
            'is_active':  self.is_active,
            'uses':       self.uses,
            'last_used':  self.last_used.isoformat() if self.last_used else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
        }
        if show_key:
            d['key'] = self.key
        else:
            d['key_preview'] = self.key[:8] + '…'
        return d


# ─────────────────────────────────────────────────────────────
#  Webhook
# ─────────────────────────────────────────────────────────────
class Webhook(db.Model):
    __tablename__ = 'webhooks'

    id          = db.Column(db.String(36), primary_key=True, default=_new_uuid)
    user_id     = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    url         = db.Column(db.String(2048), nullable=False)
    secret      = db.Column(db.String(64), nullable=False, default=_new_token)
    events      = db.Column(db.String(256), default='analysis.done')  # comma-separated
    is_active   = db.Column(db.Boolean, default=True)
    failures    = db.Column(db.Integer, default=0)
    last_fired  = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at  = db.Column(db.DateTime(timezone=True), default=_utcnow)

    user = db.relationship('User', back_populates='webhooks')

    def to_dict(self):
        return {
            'id':         self.id,
            'url':        self.url,
            'events':     self.events.split(','),
            'is_active':  self.is_active,
            'failures':   self.failures,
            'last_fired': self.last_fired.isoformat() if self.last_fired else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }