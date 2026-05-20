"""
config.py — Centralised configuration with environment-variable overrides.
"""
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # Flask
    SECRET_KEY  = os.environ.get('SECRET_KEY', 'dev-secret-key-CHANGE-ME-in-production')
    DEBUG       = os.environ.get('DEBUG', 'False').lower() == 'true'
    TESTING     = False

    # Database (SQLite by default; swap DATABASE_URL for Postgres/MySQL)
    DATA_DIR    = os.path.join(BASE_DIR, 'data')
    _default_db = 'sqlite:///' + os.path.join(BASE_DIR, 'data', 'webqa.db')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', _default_db)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True, 'pool_recycle': 300}

    # Session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 86400 * 7

    # Redis / RQ
    REDIS_URL          = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    USE_REDIS          = os.environ.get('USE_REDIS', 'False').lower() == 'true'

    # Flask-Caching
    CACHE_TYPE            = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 3600

    # Rate limiting
    RATELIMIT_STORAGE_URI = 'memory://'
    RATE_WINDOW_SECONDS   = 60
    RATE_MAX_ANALYSES     = int(os.environ.get('RATE_MAX_ANALYSES', 10))

    # Auth
    LOGIN_MAX_ATTEMPTS    = 5
    LOCKOUT_SECONDS       = 300
    JWT_EXPIRY_SECONDS    = 3600

    # Analysis / Fetch
    FETCH_TIMEOUT         = int(os.environ.get('FETCH_TIMEOUT', 15))
    MAX_HTML_SIZE_MB      = float(os.environ.get('MAX_HTML_SIZE_MB', 5))
    ANALYSIS_CACHE_TTL    = int(os.environ.get('ANALYSIS_CACHE_TTL', 3600))

    # Anthropic
    ANTHROPIC_API_KEY     = os.environ.get('ANTHROPIC_API_KEY', '')
    CHATBOT_MODEL         = os.environ.get('CHATBOT_MODEL', 'claude-haiku-4-5-20251001')
    CHATBOT_MAX_TOKENS    = 400

    # PDF Export
    PDF_DIR               = os.path.join(BASE_DIR, 'exports')

    # Webhooks
    WEBHOOK_TIMEOUT       = 5
    WEBHOOK_MAX_FAILURES  = 5

    # Admin
    ADMIN_USERNAME        = os.environ.get('ADMIN_USERNAME', 'admin')


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    CACHE_TYPE = 'RedisCache'
    RATELIMIT_STORAGE_URI = Config.REDIS_URL


config_map = {
    'development': DevelopmentConfig,
    'production':  ProductionConfig,
    'default':     DevelopmentConfig,
}


def get_config():
    env = os.environ.get('FLASK_ENV', 'default')
    return config_map.get(env, DevelopmentConfig)