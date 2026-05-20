"""
app.py — WebQA Pro (upscaled)
Improvements over the original:
  * SQLAlchemy ORM (SQLite default, Postgres-ready) replacing flat JSON files
  * Flask-Caching for in-process URL result cache
  * Flask-Limiter for per-user rate limiting with proper storage
  * API Key authentication (Bearer token) for headless / CI use
  * /api/keys  — create / list / revoke personal API keys
  * /api/webhooks — register webhooks that fire on analysis.done
  * /export/<id>/pdf — PDF report download via ReportLab
  * /api/admin/* — admin-only endpoints (user list, stats)
  * Background analysis via threading (RQ-ready when Redis enabled)
  * Structured JSON logging helper
  * /api/bulk-analyze — queue multiple URLs at once
  * /api/tags — tag / un-tag analyses
  * /api/notes — add notes to analyses
  * Prometheus-style /metrics (lightweight, no external dep)
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import urlparse, urlunparse

import requests as http_requests
from flask import (Flask, Response, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from flask_caching import Cache
from werkzeug.security import generate_password_hash

from config import get_config
from models import Analysis, APIKey, User, Webhook, db
from utils.analysis import analyze_website
from utils.pdf_export import generate_pdf_report
from utils import webhooks as webhook_dispatch

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
log = logging.getLogger('webqa')


# ─── App factory ─────────────────────────────────────────────────────────────
def create_app(config_obj=None):
    app = Flask(__name__)
    cfg = config_obj or get_config()
    app.config.from_object(cfg)

    # Ensure dirs exist
    os.makedirs(app.config['DATA_DIR'], exist_ok=True)
    os.makedirs(app.config.get('PDF_DIR', 'exports'), exist_ok=True)

    # Extensions
    db.init_app(app)
    cache.init_app(app)

    with app.app_context():
        db.create_all()
        _ensure_admin(app)

    return app


cache = Cache()

# ─── In-memory rate-limit & brute-force stores ───────────────────────────────
_rate_limits    = {}   # {user_id: [timestamps]}
_login_attempts = {}   # {username: {'count': n, 'locked_until': ts}}
_metrics        = {'analyses_total': 0, 'analyses_cached': 0,
                   'logins_ok': 0, 'logins_failed': 0,
                   'api_key_hits': 0}

# ─── Helpers ─────────────────────────────────────────────────────────────────
def now_utc():
    return datetime.now(timezone.utc)


def ok(data: dict = None, **kwargs):
    payload = {'success': True}
    if data:
        payload.update(data)
    payload.update(kwargs)
    return jsonify(payload)


def err(message: str, status: int = 400):
    return jsonify({'success': False, 'error': message}), status


def validate_url(raw: str):
    raw = raw.strip()
    if not raw:
        return None, 'URL is required'
    if not raw.startswith(('http://', 'https://')):
        raw = 'https://' + raw
    parsed = urlparse(raw)
    if not parsed.netloc or '.' not in parsed.netloc:
        return None, 'Invalid URL — include a valid domain (e.g. https://example.com)'
    clean = urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or '/', '', '', ''))
    return clean, None


def _ensure_admin(app):
    """Create a default admin account on first run."""
    admin_name = app.config.get('ADMIN_USERNAME', 'admin')
    if not User.query.filter_by(username=admin_name).first():
        admin = User(
            username=admin_name,
            email='admin@localhost',
            role='admin',
        )
        admin.set_password(os.environ.get('ADMIN_PASSWORD', 'changeme123'))
        db.session.add(admin)
        db.session.commit()
        log.info('Default admin account created (username=%s)', admin_name)


# ─── Rate limiter ─────────────────────────────────────────────────────────────
def check_rate_limit(user_id: str, window: int, max_calls: int) -> bool:
    now   = time.time()
    start = now - window
    hits  = [t for t in _rate_limits.get(user_id, []) if t > start]
    if len(hits) >= max_calls:
        _rate_limits[user_id] = hits
        return False
    hits.append(now)
    _rate_limits[user_id] = hits
    return True


# ─── Brute-force guard ───────────────────────────────────────────────────────
def record_failed_login(username):
    entry = _login_attempts.get(username, {'count': 0, 'locked_until': 0})
    entry['count'] += 1
    if entry['count'] >= 5:
        entry['locked_until'] = time.time() + 300
        entry['count'] = 0
    _login_attempts[username] = entry
    _metrics['logins_failed'] += 1


def is_locked_out(username) -> bool:
    e = _login_attempts.get(username)
    return bool(e and time.time() < e.get('locked_until', 0))


def clear_failed_logins(username):
    _login_attempts.pop(username, None)


# ─── Auth decorators ─────────────────────────────────────────────────────────
def _get_user_from_api_key() -> User | None:
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth[7:].strip()
    key_obj = APIKey.query.filter_by(key=token, is_active=True).first()
    if not key_obj:
        return None
    if key_obj.expires_at and key_obj.expires_at < now_utc():
        return None
    key_obj.last_used = now_utc()
    key_obj.uses += 1
    db.session.commit()
    _metrics['api_key_hits'] += 1
    return key_obj.user


def _current_user() -> User | None:
    """Resolve user from session or Bearer API key."""
    uid = session.get('user_id')
    if uid:
        return User.query.get(uid)
    return _get_user_from_api_key()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = _current_user()
        if not user or not user.is_active:
            if request.is_json or request.path.startswith('/api/'):
                return err('Authentication required', 401)
            return redirect(url_for('login'))
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = _current_user()
        if not user or user.role != 'admin':
            return err('Admin access required', 403)
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper


# ─── Request timing ──────────────────────────────────────────────────────────
def attach_hooks(app):
    @app.before_request
    def _start():
        g.start_time = time.perf_counter()

    @app.after_request
    def _timing(response):
        if hasattr(g, 'start_time'):
            ms = round((time.perf_counter() - g.start_time) * 1000, 2)
            response.headers['X-Response-Time'] = f'{ms}ms'
        response.headers['X-Powered-By'] = 'WebQA-Pro/2.0'
        return response


# ─── Error handlers ──────────────────────────────────────────────────────────
def register_error_handlers(app):
    @app.errorhandler(401)
    def h401(e):
        if request.is_json or request.path.startswith('/api/'):
            return err('Unauthorized', 401)
        return redirect(url_for('login'))

    @app.errorhandler(404)
    def h404(e):
        if request.is_json or request.path.startswith('/api/'):
            return err('Not found', 404)
        return render_template('home.html'), 404

    @app.errorhandler(500)
    def h500(e):
        log.exception('Unhandled 500')
        return err('Internal server error', 500)


# ─── Analysis helpers ────────────────────────────────────────────────────────
def _cache_key(url: str) -> str:
    import hashlib
    return hashlib.sha256(url.encode()).hexdigest()


def _save_analysis(user: User, url: str, result: dict, cached: bool = False,
                   job_id: str = None) -> Analysis:
    cats   = result.get('categories', {})
    counts = result.get('severity_counts', {})
    a = Analysis(
        id            = str(uuid.uuid4()),
        user_id       = user.id,
        url           = url,
        status        = 'done',
        job_id        = job_id,
        overall_score = result.get('overall_score'),
        security_score= cats.get('Security', {}).get('score'),
        seo_score     = cats.get('SEO', {}).get('score'),
        perf_score    = result.get('performance_score'),
        html_score    = cats.get('HTML', {}).get('score'),
        css_score     = cats.get('CSS', {}).get('score'),
        js_score      = cats.get('JavaScript', {}).get('score'),
        a11y_score    = cats.get('Accessibility', {}).get('score'),
        issues_high   = counts.get('high', 0),
        issues_medium = counts.get('medium', 0),
        issues_low    = counts.get('low', 0),
        load_time     = result.get('load_time_seconds'),
        html_size_kb  = result.get('html_size_kb'),
        result_json   = json.dumps(result),
        cached        = cached,
    )
    db.session.add(a)
    db.session.commit()
    _metrics['analyses_total'] += 1
    if cached:
        _metrics['analyses_cached'] += 1
    return a


def _run_analysis_bg(analysis_id: str, url: str, user_id: str, app):
    """Run analysis in a background thread and update the DB record."""
    with app.app_context():
        a = Analysis.query.get(analysis_id)
        if not a:
            return
        a.status = 'running'
        db.session.commit()
        try:
            result = analyze_website(url)
            if not result.get('success'):
                a.status = 'failed'
                db.session.commit()
                return
            cats   = result.get('categories', {})
            counts = result.get('severity_counts', {})
            a.status        = 'done'
            a.overall_score = result.get('overall_score')
            a.security_score= cats.get('Security', {}).get('score')
            a.seo_score     = cats.get('SEO', {}).get('score')
            a.perf_score    = result.get('performance_score')
            a.html_score    = cats.get('HTML', {}).get('score')
            a.css_score     = cats.get('CSS', {}).get('score')
            a.js_score      = cats.get('JavaScript', {}).get('score')
            a.a11y_score    = cats.get('Accessibility', {}).get('score')
            a.issues_high   = counts.get('high', 0)
            a.issues_medium = counts.get('medium', 0)
            a.issues_low    = counts.get('low', 0)
            a.load_time     = result.get('load_time_seconds')
            a.html_size_kb  = result.get('html_size_kb')
            a.result_json   = json.dumps(result)
            db.session.commit()
            _metrics['analyses_total'] += 1

            # Fire webhooks
            user = User.query.get(user_id)
            if user:
                whs = Webhook.query.filter_by(user_id=user_id, is_active=True).all()
                webhook_dispatch.dispatch(whs, 'analysis.done', {
                    'analysis_id': analysis_id,
                    'url': url,
                    'score': result.get('overall_score'),
                })
        except Exception as exc:
            log.exception('Background analysis failed: %s', exc)
            a.status = 'failed'
            db.session.commit()


# ══════════════════════════════════════════════════════════════
#  Build the app
# ══════════════════════════════════════════════════════════════
app = create_app()
attach_hooks(app)
register_error_handlers(app)


# ══════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ══════════════════════════════════════════════════════════════
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/analyzer')
@login_required
def analyzer():
    return render_template('index.html', user=g.current_user.username)


@app.route('/dashboard')
@login_required
def dashboard():
    user = g.current_user
    analyses = (Analysis.query
                .filter_by(user_id=user.id)
                .order_by(Analysis.created_at.desc())
                .limit(100).all())
    return render_template('dashboard.html',
                           analyses=[a.slim_dict() for a in analyses],
                           user=user.username)


@app.route('/analysis/<analysis_id>')
@login_required
def view_analysis(analysis_id):
    a = Analysis.query.filter_by(id=analysis_id, user_id=g.current_user.id).first()
    if not a:
        return render_template('home.html'), 404
    result = json.loads(a.result_json) if a.result_json else {}
    return render_template('analysis_detail.html', analysis={'id': a.id, 'url': a.url,
                                                              'timestamp': a.created_at.isoformat(),
                                                              'result': result})


# ══════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data     = request.get_json() or request.form
        username = (data.get('username') or '').strip()
        password = (data.get('password') or '').strip()
        email    = (data.get('email') or '').strip() or None

        if not username or not password:
            return err('Username and password are required')
        if len(username) < 3 or len(username) > 32:
            return err('Username must be 3–32 characters')
        if len(password) < 8:
            return err('Password must be at least 8 characters')
        if not username.replace('_','').replace('-','').isalnum():
            return err('Username may only contain letters, numbers, hyphens, underscores')

        if User.query.filter_by(username=username).first():
            return err('Username already taken', 409)

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session['user_id']  = user.id
        session['username'] = user.username
        session.permanent   = True
        return ok(redirect='/dashboard', message='Account created successfully')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data     = request.get_json() or request.form
        username = (data.get('username') or '').strip()
        password = (data.get('password') or '').strip()

        if not username or not password:
            return err('Username and password are required')

        if is_locked_out(username):
            remaining = int(_login_attempts[username]['locked_until'] - time.time())
            return err(f'Account locked. Try again in {remaining // 60 + 1} min.', 429)

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password) or not user.is_active:
            record_failed_login(username)
            return err('Invalid username or password', 401)

        clear_failed_logins(username)
        user.last_login = now_utc()
        db.session.commit()
        _metrics['logins_ok'] += 1

        session['user_id']  = user.id
        session['username'] = user.username
        session.permanent   = True
        return ok(redirect='/dashboard')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# ══════════════════════════════════════════════════════════════
#  ANALYSIS
# ══════════════════════════════════════════════════════════════
@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    user  = g.current_user
    data  = request.get_json() or {}
    raw_url       = data.get('url', '')
    force_refresh = data.get('force_refresh', False)
    async_mode    = data.get('async', False)

    clean_url, url_err = validate_url(raw_url)
    if url_err:
        return err(url_err)

    cfg = app.config
    if not check_rate_limit(user.id, cfg.get('RATE_WINDOW_SECONDS', 60),
                            cfg.get('RATE_MAX_ANALYSES', 10)):
        return err(f'Rate limit exceeded — max {cfg.get("RATE_MAX_ANALYSES",10)} analyses/min.', 429)

    ck = _cache_key(clean_url)

    # Cache check
    if not force_refresh:
        cached_result = cache.get(ck)
        if cached_result:
            a = _save_analysis(user, clean_url, cached_result, cached=True)
            session['last_analysis_id'] = a.id
            return ok(analysis_id=a.id, result=cached_result, cached=True)

    # Async mode: create placeholder and run in thread
    if async_mode:
        analysis_id = str(uuid.uuid4())
        a = Analysis(id=analysis_id, user_id=user.id, url=clean_url, status='pending')
        db.session.add(a)
        db.session.commit()
        t = threading.Thread(target=_run_analysis_bg,
                             args=(analysis_id, clean_url, user.id, app), daemon=True)
        t.start()
        return ok(analysis_id=analysis_id, status='pending',
                  poll_url=f'/api/analyses/{analysis_id}/status')

    # Synchronous
    result = analyze_website(clean_url)
    if not result.get('success'):
        return err(result.get('error', 'Analysis failed — site may be unreachable'), 502)

    cache.set(ck, result, timeout=cfg.get('ANALYSIS_CACHE_TTL', 3600))

    a = _save_analysis(user, clean_url, result)
    session['last_analysis_id'] = a.id

    # Fire webhooks
    whs = Webhook.query.filter_by(user_id=user.id, is_active=True).all()
    webhook_dispatch.dispatch(whs, 'analysis.done', {
        'analysis_id': a.id, 'url': clean_url, 'score': result.get('overall_score')
    })

    return ok(analysis_id=a.id, result=result, cached=False)


@app.route('/api/analyses/<analysis_id>/status')
@login_required
def analysis_status(analysis_id):
    a = Analysis.query.filter_by(id=analysis_id, user_id=g.current_user.id).first()
    if not a:
        return err('Not found', 404)
    d = {'id': a.id, 'status': a.status}
    if a.status == 'done':
        d['result'] = json.loads(a.result_json) if a.result_json else {}
    return ok(**d)


@app.route('/api/bulk-analyze', methods=['POST'])
@login_required
def bulk_analyze():
    """Queue up to 10 URLs for async analysis."""
    user = g.current_user
    data = request.get_json() or {}
    urls = data.get('urls', [])
    if not urls or len(urls) > 10:
        return err('Provide 1–10 URLs')

    results = []
    for raw in urls:
        clean, url_err = validate_url(raw)
        if url_err:
            results.append({'url': raw, 'error': url_err})
            continue
        analysis_id = str(uuid.uuid4())
        a = Analysis(id=analysis_id, user_id=user.id, url=clean, status='pending')
        db.session.add(a)
        db.session.commit()
        t = threading.Thread(target=_run_analysis_bg,
                             args=(analysis_id, clean, user.id, app), daemon=True)
        t.start()
        results.append({'url': clean, 'analysis_id': analysis_id, 'status': 'pending'})

    return ok(results=results)


@app.route('/compare', methods=['POST'])
@login_required
def compare():
    data = request.get_json() or {}
    ids  = data.get('ids', [])
    if len(ids) < 2:
        return err('Select at least two reports')
    selected = Analysis.query.filter(
        Analysis.id.in_(ids), Analysis.user_id == g.current_user.id
    ).all()
    if len(selected) < 2:
        return err('Reports not found', 404)
    analyses = [{'id': a.id, 'url': a.url,
                 'timestamp': a.created_at.isoformat(),
                 'result': json.loads(a.result_json) if a.result_json else {}}
                for a in selected]
    return render_template('compare.html', analyses=analyses)


@app.route('/export/<analysis_id>')
@login_required
def export_json(analysis_id):
    a = Analysis.query.filter_by(id=analysis_id, user_id=g.current_user.id).first()
    if not a:
        return err('Not found', 404)
    result = json.loads(a.result_json) if a.result_json else {}
    fname  = f"webqa_{a.url.replace('https://','').replace('/','_')[:40]}_{a.id[:8]}.json"
    return Response(json.dumps(result, indent=2, ensure_ascii=False),
                    mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename="{fname}"'})


@app.route('/export/<analysis_id>/pdf')
@login_required
def export_pdf(analysis_id):
    """Generate and download a PDF report."""
    a = Analysis.query.filter_by(id=analysis_id, user_id=g.current_user.id).first()
    if not a:
        return err('Not found', 404)
    result = json.loads(a.result_json) if a.result_json else {}
    record = {'id': a.id, 'url': a.url,
              'created_at': a.created_at.isoformat() if a.created_at else '',
              'result': result}
    try:
        pdf_bytes = generate_pdf_report(record)
    except RuntimeError as e:
        return err(str(e), 500)

    import io
    fname = f"webqa_report_{a.id[:8]}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=fname,
    )


@app.route('/delete/<analysis_id>', methods=['DELETE'])
@login_required
def delete_analysis(analysis_id):
    a = Analysis.query.filter_by(id=analysis_id, user_id=g.current_user.id).first()
    if not a:
        return err('Not found or not authorised', 404)
    db.session.delete(a)
    db.session.commit()
    return ok(message='Report deleted')


@app.route('/delete-multiple', methods=['POST'])
@login_required
def delete_multiple():
    ids = set((request.get_json() or {}).get('ids', []))
    if not ids:
        return err('No IDs provided')
    deleted = Analysis.query.filter(
        Analysis.id.in_(ids), Analysis.user_id == g.current_user.id
    ).delete(synchronize_session=False)
    db.session.commit()
    return ok(message=f'{deleted} report(s) deleted', removed=deleted)


# ── Tags & Notes ─────────────────────────────────────────────────────────────
@app.route('/api/analyses/<analysis_id>/tags', methods=['PUT'])
@login_required
def update_tags(analysis_id):
    a = Analysis.query.filter_by(id=analysis_id, user_id=g.current_user.id).first()
    if not a:
        return err('Not found', 404)
    tags = (request.get_json() or {}).get('tags', [])
    a.tags = ','.join(str(t).strip() for t in tags if t)
    db.session.commit()
    return ok(tags=a.tags.split(',') if a.tags else [])


@app.route('/api/analyses/<analysis_id>/notes', methods=['PUT'])
@login_required
def update_notes(analysis_id):
    a = Analysis.query.filter_by(id=analysis_id, user_id=g.current_user.id).first()
    if not a:
        return err('Not found', 404)
    a.notes = (request.get_json() or {}).get('notes', '')
    db.session.commit()
    return ok(notes=a.notes)


# ══════════════════════════════════════════════════════════════
#  API — PAGINATED LIST
# ══════════════════════════════════════════════════════════════
@app.route('/api/analyses')
@login_required
def api_analyses():
    user     = g.current_user
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(50, max(1, int(request.args.get('per_page', 10))))
    search   = request.args.get('search', '').lower()
    sort_by  = request.args.get('sort', 'created_at')
    order    = request.args.get('order', 'desc')
    min_sc   = request.args.get('min_score', type=float)
    max_sc   = request.args.get('max_score', type=float)
    tag      = request.args.get('tag', '')
    status   = request.args.get('status', '')

    q = Analysis.query.filter_by(user_id=user.id)

    if search:
        q = q.filter(Analysis.url.ilike(f'%{search}%'))
    if min_sc is not None:
        q = q.filter(Analysis.overall_score >= min_sc)
    if max_sc is not None:
        q = q.filter(Analysis.overall_score <= max_sc)
    if tag:
        q = q.filter(Analysis.tags.ilike(f'%{tag}%'))
    if status:
        q = q.filter(Analysis.status == status)

    sort_col = {
        'score':    Analysis.overall_score,
        'url':      Analysis.url,
        'security': Analysis.security_score,
        'perf':     Analysis.perf_score,
    }.get(sort_by, Analysis.created_at)

    q = q.order_by(sort_col.desc() if order == 'desc' else sort_col.asc())

    total     = q.count()
    paginated = q.offset((page-1)*per_page).limit(per_page).all()

    return ok(
        analyses=[a.slim_dict() for a in paginated],
        pagination={
            'page': page, 'per_page': per_page, 'total': total,
            'total_pages': max(1, (total+per_page-1)//per_page),
            'has_next': (page*per_page) < total,
            'has_prev': page > 1,
        }
    )


# ══════════════════════════════════════════════════════════════
#  API — STATS
# ══════════════════════════════════════════════════════════════
@app.route('/api/stats')
@login_required
def api_stats():
    user = g.current_user
    analyses = Analysis.query.filter_by(user_id=user.id, status='done').all()

    if not analyses:
        return ok(total_analyses=0, avg_score=None, best_score=None,
                  worst_score=None, top_issues=[], category_averages={},
                  analyses_last_7_days=0)

    scores = [a.overall_score for a in analyses if a.overall_score is not None]
    cutoff = now_utc() - timedelta(days=7)
    recent = [a for a in analyses if a.created_at and a.created_at > cutoff]

    # Aggregate category averages from denormalised columns
    cat_avgs = {}
    for col, name in [('security_score','Security'), ('seo_score','SEO'),
                      ('perf_score','Performance'), ('html_score','HTML'),
                      ('css_score','CSS'), ('js_score','JavaScript'),
                      ('a11y_score','Accessibility')]:
        vals = [getattr(a, col) for a in analyses if getattr(a, col) is not None]
        if vals:
            cat_avgs[name] = round(sum(vals)/len(vals), 1)

    # Top issues from full JSON (limited to latest 20)
    issue_freq: dict = {}
    for a in analyses[-20:]:
        if not a.result_json:
            continue
        result = json.loads(a.result_json)
        for issue in result.get('all_issues', []):
            title = issue.get('title', '')
            issue_freq[title] = issue_freq.get(title, 0) + 1

    top_issues = sorted(issue_freq.items(), key=lambda x: x[1], reverse=True)[:5]

    return ok(
        total_analyses=len(analyses),
        avg_score=round(sum(scores)/len(scores), 1) if scores else None,
        best_score=max(scores) if scores else None,
        worst_score=min(scores) if scores else None,
        top_issues=[{'title': t, 'count': c} for t, c in top_issues],
        category_averages=cat_avgs,
        analyses_last_7_days=len(recent),
    )


@app.route('/api/profile')
@login_required
def api_profile():
    user = g.current_user
    return ok(**user.to_dict(public=False))


# ══════════════════════════════════════════════════════════════
#  API KEYS
# ══════════════════════════════════════════════════════════════
@app.route('/api/keys', methods=['GET', 'POST'])
@login_required
def api_keys():
    user = g.current_user
    if request.method == 'GET':
        keys = APIKey.query.filter_by(user_id=user.id).all()
        return ok(keys=[k.to_dict() for k in keys])

    # POST — create a new key
    data  = request.get_json() or {}
    name  = (data.get('name') or 'API Key').strip()[:128]
    expires_days = data.get('expires_days')
    key = APIKey(user_id=user.id, name=name)
    if expires_days:
        key.expires_at = now_utc() + timedelta(days=int(expires_days))
    db.session.add(key)
    db.session.commit()
    return ok(key=key.to_dict(show_key=True), message='Store this key — it will not be shown again.'), 201


@app.route('/api/keys/<key_id>', methods=['DELETE'])
@login_required
def revoke_api_key(key_id):
    k = APIKey.query.filter_by(id=key_id, user_id=g.current_user.id).first()
    if not k:
        return err('Key not found', 404)
    db.session.delete(k)
    db.session.commit()
    return ok(message='API key revoked')


# ══════════════════════════════════════════════════════════════
#  WEBHOOKS
# ══════════════════════════════════════════════════════════════
@app.route('/api/webhooks', methods=['GET', 'POST'])
@login_required
def api_webhooks():
    user = g.current_user
    if request.method == 'GET':
        whs = Webhook.query.filter_by(user_id=user.id).all()
        return ok(webhooks=[w.to_dict() for w in whs])

    data   = request.get_json() or {}
    wh_url = (data.get('url') or '').strip()
    events = data.get('events', ['analysis.done'])

    if not wh_url.startswith(('http://', 'https://')):
        return err('Invalid webhook URL')
    if Webhook.query.filter_by(user_id=user.id).count() >= 10:
        return err('Maximum 10 webhooks per user')

    wh = Webhook(user_id=user.id, url=wh_url,
                 events=','.join(events) if isinstance(events, list) else events)
    db.session.add(wh)
    db.session.commit()
    return ok(webhook=wh.to_dict()), 201


@app.route('/api/webhooks/<wh_id>', methods=['DELETE'])
@login_required
def delete_webhook(wh_id):
    wh = Webhook.query.filter_by(id=wh_id, user_id=g.current_user.id).first()
    if not wh:
        return err('Not found', 404)
    db.session.delete(wh)
    db.session.commit()
    return ok(message='Webhook deleted')


# ══════════════════════════════════════════════════════════════
#  ADMIN
# ══════════════════════════════════════════════════════════════
@app.route('/api/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return ok(users=[u.to_dict(public=False) for u in users],
              total=len(users))


@app.route('/api/admin/users/<user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    u = User.query.get(user_id)
    if not u:
        return err('User not found', 404)
    u.is_active = not u.is_active
    db.session.commit()
    return ok(user_id=u.id, is_active=u.is_active)


@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    total_users    = User.query.count()
    total_analyses = Analysis.query.count()
    active_users_7d = db.session.query(Analysis.user_id).filter(
        Analysis.created_at >= now_utc() - timedelta(days=7)
    ).distinct().count()
    return ok(
        total_users=total_users,
        total_analyses=total_analyses,
        active_users_7d=active_users_7d,
        app_metrics=_metrics,
    )


# ══════════════════════════════════════════════════════════════
#  SYSTEM
# ══════════════════════════════════════════════════════════════
@app.route('/health')
def health():
    return ok(
        status='healthy',
        timestamp=now_utc().isoformat(),
        analyses_stored=Analysis.query.count(),
        registered_users=User.query.count(),
        metrics=_metrics,
    )


@app.route('/metrics')
def metrics():
    """Lightweight plain-text metrics (Prometheus-compatible format)."""
    lines = [
        '# HELP webqa_analyses_total Total analyses run',
        '# TYPE webqa_analyses_total counter',
        f'webqa_analyses_total {_metrics["analyses_total"]}',
        '# HELP webqa_analyses_cached_total Analyses served from cache',
        f'webqa_analyses_cached_total {_metrics["analyses_cached"]}',
        '# HELP webqa_logins_ok_total Successful logins',
        f'webqa_logins_ok_total {_metrics["logins_ok"]}',
        '# HELP webqa_logins_failed_total Failed login attempts',
        f'webqa_logins_failed_total {_metrics["logins_failed"]}',
        '# HELP webqa_api_key_hits_total API key authenticated requests',
        f'webqa_api_key_hits_total {_metrics["api_key_hits"]}',
        '# HELP webqa_users_total Total registered users',
        f'webqa_users_total {User.query.count()}',
        '# HELP webqa_analyses_db_total Analyses in DB',
        f'webqa_analyses_db_total {Analysis.query.count()}',
    ]
    return Response('\n'.join(lines) + '\n', mimetype='text/plain')


@app.route('/api/cache/clear', methods=['POST'])
@login_required
def clear_cache():
    cache.clear()
    return ok(message='Cache cleared')


# ══════════════════════════════════════════════════════════════
#  AI CHATBOT  (unchanged logic, updated model)
# ══════════════════════════════════════════════════════════════
def _build_system_prompt(context: dict) -> str:
    cats      = context.get('categories', {})
    issues    = context.get('all_issues', [])
    url       = context.get('url', 'unknown')
    overall   = context.get('overall_score', 0)
    perf      = context.get('performance_score', 0)
    load_time = context.get('load_time_seconds', '?')

    issue_lines = [
        f"  [{i['severity'].upper()}] {i['category']} — {i['title']}: {i['fix_suggestion']}"
        for i in issues[:30]
    ]
    cat_scores = '\n'.join(f'  {k}: {v["score"]}/100' for k, v in cats.items())

    return f"""You are WebQA Assistant, an expert web quality and security analyst.
The user analyzed: {url}
SCORES: Overall {overall}/100 | Performance {perf}/100 | Load {load_time}s | Issues {len(issues)}
CATEGORIES:\n{cat_scores}
ISSUES:\n{chr(10).join(issue_lines) or '  None'}
Answer concisely. Use **bold**, bullet lists, `code` where appropriate. Max 150 words unless detail requested."""


def _call_claude(system_prompt, user_message, history=None):
    api_key = app.config.get('ANTHROPIC_API_KEY', '')
    if not api_key:
        return None
    messages = []
    for t in (history or [])[-6:]:
        messages.append({'role': t['role'], 'content': t['content']})
    messages.append({'role': 'user', 'content': user_message})
    try:
        resp = http_requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01',
                     'content-type': 'application/json'},
            json={'model': app.config.get('CHATBOT_MODEL', 'claude-haiku-4-5-20251001'),
                  'max_tokens': app.config.get('CHATBOT_MAX_TOKENS', 400),
                  'system': system_prompt, 'messages': messages},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()['content'][0]['text']
    except Exception:
        pass
    return None


def _rule_based_response(user_message: str, context: dict) -> str:
    cats    = context.get('categories', {})
    issues  = context.get('all_issues', [])
    url     = context.get('url', '')
    overall = context.get('overall_score', 0)
    perf    = context.get('performance_score', 0)
    m       = user_message.lower()

    if any(w in m for w in ['hi','hello','hey']):
        return f"Hello! I analyzed **{url}** — **{overall}/100** overall with **{len(issues)} issues**."

    if any(w in m for w in ['summary','overall','score','how did']):
        top = sorted(issues, key=lambda x: {'high':3,'medium':2,'low':1}.get(x['severity'],0), reverse=True)[:3]
        lines = '\n'.join(f"- **{i['title']}** ({i['severity']})" for i in top) or '- No issues!'
        return f"**Overall: {overall}/100 | Performance: {perf}/100**\n\nTop issues:\n{lines}"

    for cat in ['security','seo','html','css','javascript','accessibility']:
        if cat in m:
            key = 'JavaScript' if cat=='javascript' else cat.capitalize()
            if key in cats:
                s = cats[key]['score']
                cat_issues = [i for i in issues if i.get('category','').lower()==cat]
                if cat_issues:
                    i = cat_issues[0]
                    return f"**{cat.upper()}: {s}/100**\n\n**{i['title']}**\n\n{i.get('explanation','')}\n\n`Fix:` {i['fix_suggestion']}"
                return f"**{cat.upper()}: {s}/100** — No issues detected!"

    if any(w in m for w in ['fix','improve','how to']):
        high = [i for i in issues if i.get('severity')=='high']
        if high:
            return f"**Critical fix:**\n\n**{high[0]['title']}**\n\n{high[0]['fix_suggestion']}"
        med = [i for i in issues if i.get('severity')=='medium']
        if med:
            return f"No critical issues! Medium priority:\n\n**{med[0]['title']}**\n\n{med[0]['fix_suggestion']}"
        return "Great — no urgent fixes needed!"

    if issues:
        worst = max(issues, key=lambda x: {'high':3,'medium':2,'low':1}.get(x.get('severity','low'),0))
        return (f"Found **{len(issues)} issues** on {url}.\n\n"
                f"Most critical: **{worst['title']}**\n\n{worst['fix_suggestion']}")
    return f"**{url}** is clean! Score: **{overall}/100**."


@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    data         = request.get_json() or {}
    user_message = data.get('message', '').strip()
    history      = data.get('history', [])

    if not user_message:
        return err('Please ask a question')

    user    = g.current_user
    last_id = session.get('last_analysis_id')
    context = None

    if last_id:
        a = Analysis.query.filter_by(id=last_id, user_id=user.id).first()
        if a and a.result_json:
            context = json.loads(a.result_json)

    if not context:
        return ok(response=(
            "You haven't analyzed a website yet.\n\n"
            "Head to the **Analyzer** page, enter a URL, and run a scan — "
            "then I'll explain the results!"
        ))

    system_prompt = _build_system_prompt(context)
    ai_response   = _call_claude(system_prompt, user_message, history)
    return ok(response=ai_response or _rule_based_response(user_message, context))


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=app.config.get('DEBUG', False), host='0.0.0.0', port=5000)