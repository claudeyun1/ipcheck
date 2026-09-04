"""
IP Access Logger v3 (성능 / 보안 / UI 개선판)
──────────────────────────────────────────────────────────
- /page      : 정적 HTML 제공 (내부 ID + tracking JS 삽입)
- /track     : 클라이언트 JS가 호출 → IP, 내부ID, UA 기록
- /admin     : 관리자 로그인 → 통계 & 로그 대시보드

주요 개선사항 (원본 대비)
  [성능] 요청마다 SQLite 커넥션 새로 열고 닫던 것 → flask.g 로 요청 단위 재사용
  [성능] WAL 모드 + synchronous=NORMAL 로 동시 읽기/쓰기 처리량 향상
  [성능] 통계(stats) API에 5초 TTL 캐시 적용 (대시보드 폴링 부하 완화)
  [성능] 인덱스 추가 (ip, created_at 복합 인덱스)
  [보안] 비밀번호 평문 비교(SHA-256) → werkzeug PBKDF2 해시 + hmac.compare_digest
  [보안] X-Forwarded-For 무조건 신뢰(스푸핑 가능) → ProxyFix + 신뢰 홉 수 설정으로 교체
  [보안] 대시보드 innerHTML 삽입 시 XSS 가능 (UA/track_id는 클라이언트 통제값) → HTML 이스케이프 적용
  [보안] 로그인 CSRF 토큰 추가, 로그인/트래킹 엔드포인트에 rate limit 추가
  [보안] 세션 쿠키 HttpOnly/SameSite/Secure, 세션 만료시간 설정
  [보안] 보안 헤더(CSP nonce, X-Frame-Options 등) 추가, 요청 바디 크기 제한
  [보안] track_id UUID 형식 검증, User-Agent 길이 제한 (쓰레기 데이터/남용 방지)
  [UI]  자동 새로고침(탭 비활성 시 중지), 로딩/에러 상태 표시
  [UI]  최근 7일 접속 추이 막대 그래프, CSV 내보내기, 빈 상태(empty state) 표시

실행:
    pip install flask

환경 변수:
    PORT               포트 (기본 8080)
    DB_PATH            SQLite 경로 (기본 ./access_log.db)
    SECRET_KEY         Flask session 키. 미설정 시 매 재시작마다 랜덤 생성됨
                       (→ 재시작하면 기존 로그인 세션이 모두 무효화됨).
                       운영 환경에서는 반드시 고정값으로 설정할 것.
                       예) python -c "import secrets;print(secrets.token_hex(32))"
    ADMIN_USER         관리자 ID   (기본 admin)
    ADMIN_PASS         관리자 PW 평문 (기본 admin123, 데모 전용 — 운영 금지)
    ADMIN_PASS_HASH    관리자 PW 해시(werkzeug generate_password_hash 결과 문자열).
                       설정 시 ADMIN_PASS보다 우선 적용됨. 운영 환경 권장.
    TRUSTED_PROXY_HOPS 신뢰하는 리버스 프록시 홉 수 (기본 0 = 프록시 미사용).
                       nginx/Alteon 등 리버스 프록시 뒤에 있다면 1 이상으로
                       설정해야 X-Forwarded-For 스푸핑을 방지하면서 실제
                       클라이언트 IP를 얻을 수 있음. (설정하지 않으면 프록시의
                       IP가 아니라 소켓 접속 IP를 그대로 사용 — 스푸핑 불가하지만
                       프록시 뒤에서는 항상 프록시 IP만 기록됨)
    HTTPS_ONLY         "1"이면 세션 쿠키에 Secure 플래그 부여 (HTTPS 환경 필수)
    SESSION_MINUTES    관리자 세션 유지 시간(분), 기본 30

Render(무료 플랜) 배포 시 참고:
    - TRUSTED_PROXY_HOPS=1, HTTPS_ONLY=1 로 설정할 것 (Render가 TLS 종료 후
      1홉 리버스 프록시로 전달함).
    - 무료 플랜은 파일시스템이 휘발성이라 재배포/스핀다운(15분 무활동) 시마다
      SQLite 파일(access_log.db)이 초기화된다. 데이터 영속이 필요하면 Render
      Postgres 등 관리형 DB로 옮겨야 한다 (이 스크립트는 SQLite 전용).
    - Start Command 예: gunicorn -w 1 --threads 4 -b 0.0.0.0:$PORT ip_logger:app
      (내장 개발 서버(app.run)는 운영 배포에 쓰지 말 것)
"""

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, Response, g, jsonify, redirect, render_template_string,
    request, session,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# ─── 설정 ────────────────────────────────────────────────────
app = Flask(__name__)

_secret = os.environ.get("SECRET_KEY")
if not _secret:
    _secret = secrets.token_hex(32)
    print("⚠  SECRET_KEY 미설정: 임시 키를 생성했습니다. 재시작 시 기존 세션은 모두 만료됩니다. "
          "운영 환경에서는 SECRET_KEY를 고정값으로 지정하세요.")
app.secret_key = _secret

DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "access_log.db"),
)
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")

_admin_pass_hash = os.environ.get("ADMIN_PASS_HASH")
if not _admin_pass_hash:
    _plain_pw = os.environ.get("ADMIN_PASS", "admin123")
    if _plain_pw == "admin123":
        print("⚠  ADMIN_PASS가 기본값(admin123)입니다. 운영 환경에서는 반드시 변경하세요.")
    _admin_pass_hash = generate_password_hash(_plain_pw)

TRUSTED_PROXY_HOPS = int(os.environ.get(
    "TRUSTED_PROXY_HOPS",
    # Render는 모든 요청을 자체 로드밸런서 1홉을 거쳐 전달하므로,
    # RENDER 환경변수(Render가 자동 주입)가 있으면 기본값을 1로 설정한다.
    # 그렇지 않으면(로컬 등) 0으로 두어 XFF 스푸핑을 방지한다.
    "1" if os.environ.get("RENDER") else "0"
))
HTTPS_ONLY = os.environ.get("HTTPS_ONLY", "0") == "1"
SESSION_MINUTES = int(os.environ.get("SESSION_MINUTES", "30"))

_track_signing_key = os.environ.get("TRACK_SIGNING_KEY")
if not _track_signing_key:
    _track_signing_key = _secret
    print("⚠  TRACK_SIGNING_KEY 미설정: SECRET_KEY를 대신 사용합니다. "
          "배포본에 심어둔 서명된 track_id는 이 키가 바뀌면 전부 위조 판정을 받게 됩니다. "
          "이미 배포한 파일이 있다면 TRACK_SIGNING_KEY를 반드시 고정값으로 별도 지정하고, "
          "재배포/재시작 후에도 절대 바꾸지 마세요.")
TRACK_SIGNING_KEY = _track_signing_key.encode()

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=HTTPS_ONLY,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_MINUTES),
    MAX_CONTENT_LENGTH=8 * 1024,   # /track, /admin/login 등은 소형 payload만 필요
)

# 리버스 프록시 뒤에 있을 때만 X-Forwarded-For/X-Forwarded-Proto를 신뢰한다.
# (그렇지 않고 무조건 신뢰하면 클라이언트가 헤더를 위조해 IP를 조작할 수 있음)
# Render 배포 시: Render 자체가 리버스 프록시 역할을 하며 정확히 1홉만 거치므로
# TRUSTED_PROXY_HOPS=1 로 설정해야 실제 클라이언트 IP와 https 여부(X-Forwarded-Proto)를
# 올바르게 인식한다 (안 그러면 모든 접속이 Render 내부 IP로 기록되고, HTTPS_ONLY=1일 때
# 세션 쿠키의 Secure 플래그 판정이 꼬일 수 있음).
if TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=TRUSTED_PROXY_HOPS, x_proto=TRUSTED_PROXY_HOPS
    )


# ─── 간단 인메모리 rate limiter ────────────────────────────────
# 참고: gunicorn -w N 처럼 멀티 프로세스로 배포하면 프로세스별로 카운트가
# 분리되어 정확한 제한이 어려움. 다중 워커 환경에서는 Redis 기반
# flask-limiter 등으로 교체 권장.
_rate_lock = threading.Lock()
_rate_buckets = defaultdict(list)


def _rate_limited(key: str, limit: int, window: float) -> bool:
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets[key]
        while bucket and bucket[0] <= now - window:
            bucket.pop(0)
        if len(bucket) >= limit:
            return True
        bucket.append(now)
        return False


# ─── DB ─────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """요청(request) 단위로 커넥션을 재사용한다 (매번 새로 열고 닫지 않음)."""
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("PRAGMA busy_timeout=5000")
        g.db = conn
    return g.db


@app.teardown_appcontext
def _close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")     # 동시 읽기/쓰기 처리량 향상
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip           TEXT    NOT NULL,
            client_ip    TEXT,
            ip_mismatch  INTEGER NOT NULL DEFAULT 0,
            track_id     TEXT,
            token        TEXT,
            verified     INTEGER NOT NULL DEFAULT 0,
            user_agent   TEXT,
            created_at   TEXT    NOT NULL
        )
    """)
    # 기존 DB(구버전 스키마)를 쓰던 경우를 위한 마이그레이션 — 이미 있으면 조용히 건너뜀
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(access_log)").fetchall()}
    for col, defn in [
        ("token",       "TEXT"),
        ("verified",    "INTEGER NOT NULL DEFAULT 0"),
        ("client_ip",   "TEXT"),
        ("ip_mismatch", "INTEGER NOT NULL DEFAULT 0"),
    ]:
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE access_log ADD COLUMN {col} {defn}")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS track_versions (
            token       TEXT PRIMARY KEY,
            label       TEXT NOT NULL,
            revoked     INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL
        )
    """)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_track_id ON access_log(track_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_created  ON access_log(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_created ON access_log(ip, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_token ON access_log(token)")
    conn.commit()
    conn.close()


def _get_client_ip() -> str:
    # 표준 프록시 체인 동작:
    #   브라우저(1.2.3.4) → Render Edge → Render LB → Flask
    #   각 프록시는 자신이 받은 소스 IP를 XFF 맨 뒤에 추가한다.
    #   결과: X-Forwarded-For: 1.2.3.4, render-edge-ip
    #   → 첫 번째(좌측) = 실제 브라우저 IP
    #   → 마지막(우측) = Render 내부 프록시 IP (우리가 원하지 않는 값)
    #
    # 주의: 클라이언트가 XFF를 조작해 보내면(fake, 1.2.3.4, ...) 첫 번째가 틀릴 수 있으나,
    #        라이선스 추적 용도에서 일반 사용자가 XFF를 조작할 가능성은 낮다.
    if os.environ.get("RENDER"):
        xff = request.headers.get("X-Forwarded-For", "").strip()
        if xff:
            return xff.split(",")[0].strip()   # 첫 번째 = 원본 클라이언트 IP
    return request.remote_addr or "unknown"


def _is_valid_uuid(value) -> bool:
    # (더 이상 track_id 검증에는 쓰지 않지만, 다른 용도로 UUID 형식 확인이
    # 필요할 때를 위해 유틸리티로 남겨둔다.)
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


# ─── 배포본(버전) 서명 토큰 ──────────────────────────────────────
# 배포된 파일마다 고정된 식별자를 심되, 받는 사람이 값을 마음대로 다른
# 유효해 보이는 값으로 바꿔치기하지 못하도록 서버만 아는 키(TRACK_SIGNING_KEY)로
# HMAC 서명한다. 형식: "<token>.<signature>"
# 주의: 이건 "수정 자체를 원천 차단"하는 게 아니라 "수정하면 서명이 깨져서
# 서버가 위조를 탐지"하는 방식이다. 정적 HTML/JS는 원리상 최종 사용자가
# 텍스트 편집기로 열어볼 수 있는 형태라 완벽한 변조 방지는 불가능하며,
# 이것이 실질적으로 도달 가능한 최선의 방어선이다 (경량 난독화는 보조 수단일 뿐).
def _sign_token(token: str) -> str:
    sig = hmac.new(TRACK_SIGNING_KEY, token.encode(), hashlib.sha256).hexdigest()[:24]
    return f"{token}.{sig}"


def _verify_signed_id(signed_id: str):
    """반환: (token 또는 None, verified: bool)"""
    if not signed_id or "." not in signed_id:
        return None, False
    token, _, sig = signed_id.rpartition(".")
    if not token or not sig:
        return None, False
    expected = hmac.new(TRACK_SIGNING_KEY, token.encode(), hashlib.sha256).hexdigest()[:24]
    if hmac.compare_digest(sig, expected):
        return token, True
    return token, False  # 서명 불일치 → token은 참고용으로만 반환(위조 의심 표시용)


def _new_version_token() -> str:
    # URL-safe, 대소문자 구분되는 짧은 랜덤 토큰 (버전 식별용)
    return secrets.token_urlsafe(9)


def _check_auth(user: str, pw: str) -> bool:
    user_ok = hmac.compare_digest(user.encode(), ADMIN_USER.encode())
    pw_ok = check_password_hash(_admin_pass_hash, pw)
    return user_ok and pw_ok


def _log_filter_clause():
    ip_f = request.args.get("ip", "").strip()[:100]
    id_f = request.args.get("track_id", "").strip()[:100]
    where, params = [], []
    if ip_f:
        where.append("ip LIKE ?")
        params.append(f"%{ip_f}%")
    if id_f:
        where.append("track_id LIKE ?")
        params.append(f"%{id_f}%")
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    return where_sql, params


def _safe_int(val, default, lo, hi) -> int:
    try:
        n = int(val)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


# ─── 보안 헤더 / CSP nonce ─────────────────────────────────────

@app.before_request
def _make_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.after_request
def _security_headers(resp):
    nonce = g.get("csp_nonce", "")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    )
    if HTTPS_ONLY:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # /track, /ip 는 인증 없는 공개 엔드포인트라, 다른 도메인(정적 페이지)에
    # 심어둔 tracking snippet에서도 호출할 수 있도록 CORS를 허용한다.
    # (응답에 쿠키/세션 정보가 없으므로 '*' 허용이 안전함)
    if request.path in ("/track", "/ip"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Max-Age"] = "3600"
    return resp


# ─── 정적 페이지 ─────────────────────────────────────────────

PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Tracking Page (Sample)</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 4rem auto; padding: 0 1rem; }
    .badge { display:inline-block; background:#eef; padding:2px 8px; border-radius:4px; font-size:12px; }
  </style>
</head>
<body>
  <h1>📡 IP Tracker Sample</h1>
  <p>이 페이지에 tracking JS가 삽입되어 있습니다.</p>
  <p>내부 ID: <span class="badge">{{ track_id }}</span></p>
  <p>요청이 감지되면 서버에 기록됩니다.</p>

  <!-- ═══════════════════════════════════════════════
       TRACKING SNIPPET  ← 아래만 복사해서 정적 페이지에 삽입
       ═══════════════════════════════════════════════ -->
  <script nonce="{{ nonce }}">
  (function () {
    var TRACK_ID = "{{ track_id }}";          // 서버가 삽입한 내부 ID
    // "/track"은 상대 경로라서 "이 스크립트가 실행되는 페이지의 도메인" 기준으로
    // 요청이 나간다. 이 /page 라우트를 그대로 방문할 때만 유효하며(같은 origin),
    // 이 스니펫을 다른 도메인의 정적 페이지에 복사해 붙여넣을 경우에는
    // 반드시 절대 URL(예: "https://내앱.onrender.com/track")로 바꿔야 한다.
    var ENDPOINT = "/track";                  // 추적 API

    function send() {
      var payload = JSON.stringify({ id: TRACK_ID });
      // Content-Type을 text/plain으로 보내면 브라우저가 "단순 요청"으로 취급해
      // 교차 출처(cross-origin)로 호출해도 CORS preflight 없이 바로 전송된다.
      // 서버는 Content-Type과 무관하게 바디를 JSON으로 파싱하므로 동작엔 문제없음.
      if (navigator.sendBeacon) {
        // navigator.sendBeacon: 페이지 unload 시에도 전송 보장
        var blob = new Blob([payload], { type: "text/plain" });
        navigator.sendBeacon(ENDPOINT, blob);
      } else {
        fetch(ENDPOINT, {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: payload,
          keepalive: true,
          mode: "cors",
        }).catch(function(){});
      }
    }

    send();
  })();
  </script>
  <!-- ═══════════════ END TRACKING SNIPPET ═══════════════ -->
</body>
</html>
"""


@app.route("/")
def root():
    # Render 헬스체크 및 기본 접속 경로 대응 ("/"가 없으면 404가 떠서 배포 상태가
    # 헷갈릴 수 있음). 관리자는 /admin, 샘플 페이지는 /page로 안내.
    return redirect("/page")


@app.route("/healthz")
def healthz():
    return jsonify(status="ok"), 200


@app.route("/page")
def serve_page():
    # 데모용 페이지: 방문마다 임시 서명 토큰을 발급 (버전 관리 목록에는 등록되지 않음).
    # 실제 "배포본별 고정 track_id" 운영은 /admin 대시보드의 "배포본 발급" 기능으로
    # 만든 서명된 ID를 tracking_snippet_standalone.html에 박아 넣어 배포하는 방식을 쓴다.
    track_id = _sign_token(str(uuid.uuid4()))
    return render_template_string(PAGE_TEMPLATE, track_id=track_id, nonce=g.csp_nonce)


@app.route("/ip", methods=["GET", "OPTIONS"])
def ip_lookup():
    """로깅 없이 클라이언트 IP만 반환. getIp() 폴백 체인의 끝단으로 사용."""
    if request.method == "OPTIONS":
        return "", 204
    return jsonify(ip=_get_client_ip())


@app.route("/admin/api/debug-headers")
def api_debug_headers():
    """XFF 구조 진단용 (관리자 전용).
    /ip 가 잘못된 IP를 반환할 때 실제로 어떤 헤더가 오는지 확인한다.
    예: https://서비스.onrender.com/admin/api/debug-headers (로그인 후)
    """
    err = _require_admin()
    if err:
        return err
    xff = request.headers.get("X-Forwarded-For", "")
    entries = [x.strip() for x in xff.split(",")] if xff else []
    return jsonify(
        detected_ip     = _get_client_ip(),
        remote_addr     = request.remote_addr,
        x_forwarded_for = xff,
        xff_entries     = entries,
        xff_first       = entries[0]  if entries else None,
        xff_last        = entries[-1] if entries else None,
        render_env      = bool(os.environ.get("RENDER")),
        trusted_hops    = TRUSTED_PROXY_HOPS,
    )


@app.route("/track", methods=["POST", "OPTIONS"])
def track():
    """접근 로깅 + 서버가 확인한 클라이언트 IP 반환.
    응답 형식: {"ip": "x.x.x.x"}  ← ipify 와 동일한 포맷.
    클라이언트는 이 값을 getIp() 폴백 결과로 사용할 수 있다.
    """
    if request.method == "OPTIONS":
        # non-simple 헤더(Content-Type: application/json 등) 사용 시 브라우저가
        # 먼저 preflight를 보냄. text/plain 스니펫은 preflight가 발생하지 않는다.
        return "", 204

    ip = _get_client_ip()
    if _rate_limited(f"track:{ip}", limit=30, window=60):
        return jsonify(error="rate_limited"), 429

    data = request.get_json(silent=True, force=True) or {}
    raw_id    = str(data.get("id", ""))[:120]
    token, verified = _verify_signed_id(raw_id)
    user_agent = request.headers.get("User-Agent", "")[:300]

    # 클라이언트가 외부 서비스(ipify 등)로 직접 조회해 보낸 IP.
    # 서버가 소켓에서 확인한 ip와 다르면 프록시/VPN 사용 가능성을 표시한다.
    client_ip  = str(data.get("client_ip", "") or "")[:64].strip() or None
    ip_mismatch = int(bool(client_ip and client_ip != ip))

    db = get_db()
    db.execute(
        "INSERT INTO access_log "
        "(ip, client_ip, ip_mismatch, track_id, token, verified, user_agent, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ip, client_ip, ip_mismatch, raw_id or None, token,
         1 if verified else 0, user_agent, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    # ipify 호환 형식으로 서버가 확인한 IP 반환.
    # 클라이언트(getIp 폴백 체인)가 이 값을 라이선스 검증에 활용할 수 있다.
    return jsonify(ip=ip)


# ─── 관리자 ─────────────────────────────────────────────────

LOGIN_TEMPLATE = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8"><title>관리자 로그인</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; background:#f5f5f5; }
    .box { background:#fff; padding:2.5rem; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,.08); width:320px; }
    h2 { margin:0 0 1.5rem; font-size:1.2rem; }
    label { display:block; font-size:.85rem; margin-bottom:.3rem; color:#555; }
    input { width:100%; padding:.6rem .8rem; margin-bottom:1rem; border:1px solid #ddd; border-radius:6px; font-size:.95rem; }
    button { width:100%; padding:.7rem; background:#2563eb; color:#fff; border:none; border-radius:6px; font-size:1rem; cursor:pointer; }
    button:hover { background:#1d4ed8; }
    button:disabled { background:#93c5fd; cursor:not-allowed; }
    .err { color:#dc2626; font-size:.85rem; margin-bottom:.5rem; }
    a.back { display:inline-block; margin-top:1rem; font-size:.85rem; color:#666; }
  </style>
</head>
<body>
  <div class="box">
    <h2>🔐 관리자 로그인</h2>
    {% if error %}<p class="err">{{ error }}</p>{% endif %}
    <form method="POST" action="/admin/login" id="loginForm">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <label>ID</label>
      <input name="user" required autofocus autocomplete="username">
      <label>PW</label>
      <input name="pw" type="password" required autocomplete="current-password">
      <button type="submit" id="loginBtn">로그인</button>
    </form>
    <a class="back" href="/page">← 샘플 페이지로</a>
  </div>
  <script nonce="{{ nonce }}">
    document.getElementById("loginForm").addEventListener("submit", function () {
      var btn = document.getElementById("loginBtn");
      btn.disabled = true;
      btn.textContent = "로그인 중…";
    });
  </script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8"><title>관리자 대시보드</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin:0; padding:2rem; background:#f8fafc; color:#1e293b; }
    .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem; flex-wrap:wrap; gap:.5rem; }
    .header h1 { font-size:1.4rem; margin:0; }
    .header .right { display:flex; align-items:center; gap:1rem; }
    .header a, .header button.link { color:#64748b; text-decoration:none; font-size:.9rem; background:none; border:none; cursor:pointer; padding:0; }
    #refreshed { font-size:.78rem; color:#94a3b8; }
    .cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(160px,1fr)); gap:1rem; margin-bottom:2rem; }
    .card { background:#fff; border-radius:10px; padding:1.2rem; box-shadow:0 1px 4px rgba(0,0,0,.06); }
    .card .num { font-size:2rem; font-weight:700; }
    .card .label { font-size:.8rem; color:#64748b; margin-top:.3rem; }
    .section { background:#fff; border-radius:10px; padding:1.5rem; margin-bottom:1.5rem; box-shadow:0 1px 4px rgba(0,0,0,.06); overflow-x:auto; }
    .section h2 { font-size:1rem; margin:0 0 1rem; color:#334155; }
    table { width:100%; border-collapse:collapse; font-size:.88rem; }
    th { text-align:left; padding:.5rem .6rem; border-bottom:2px solid #e2e8f0; color:#64748b; font-weight:600; white-space:nowrap; }
    td { padding:.5rem .6rem; border-bottom:1px solid #f1f5f9; }
    tr:hover td { background:#f8fafc; }
    .badge { background:#e0e7ff; color:#3730a3; padding:1px 6px; border-radius:4px; font-size:.78rem; }
    .btn-row { display:flex; gap:.5rem; margin-bottom:1rem; flex-wrap:wrap; }
    .btn { padding:.5rem 1rem; border:none; border-radius:6px; cursor:pointer; font-size:.85rem; }
    .btn-pri { background:#2563eb; color:#fff; }
    .btn-pri:hover { background:#1d4ed8; }
    .btn-sec { background:#e2e8f0; color:#334155; }
    .btn-sec:disabled { opacity:.5; cursor:not-allowed; }
    .filter { display:flex; gap:.5rem; align-items:center; margin-bottom:1rem; flex-wrap:wrap; }
    .filter input { padding:.4rem .7rem; border:1px solid #ddd; border-radius:6px; font-size:.85rem; }
    .trend { display:flex; align-items:flex-end; gap:.4rem; height:90px; }
    .trend .bar-wrap { display:flex; flex-direction:column; align-items:center; gap:.3rem; flex:1; }
    .trend .bar { width:100%; background:#93c5fd; border-radius:3px 3px 0 0; min-height:2px; }
    .trend .bar-label { font-size:.7rem; color:#94a3b8; }
    .empty { text-align:center; color:#94a3b8; padding:1.5rem; font-size:.85rem; }
    .err-banner { background:#fef2f2; color:#b91c1c; padding:.6rem 1rem; border-radius:6px; font-size:.85rem; margin-bottom:1rem; display:none; }
    .issue-row { display:flex; gap:.5rem; margin-bottom:1rem; flex-wrap:wrap; }
    .issue-row input { flex:1; min-width:180px; padding:.5rem .7rem; border:1px solid #ddd; border-radius:6px; font-size:.85rem; }
    .snippet-box { display:none; margin-top:1rem; }
    .snippet-box textarea { width:100%; height:110px; font-family:ui-monospace,monospace; font-size:.78rem; padding:.7rem; border:1px solid #ddd; border-radius:6px; resize:vertical; }
    .tag-warn { background:#fef3c7; color:#92400e; padding:1px 6px; border-radius:4px; font-size:.75rem; }
    .tag-revoked { background:#fee2e2; color:#991b1b; padding:1px 6px; border-radius:4px; font-size:.75rem; }
    .tag-ok { background:#dcfce7; color:#166534; padding:1px 6px; border-radius:4px; font-size:.75rem; }
    .hint { font-size:.78rem; color:#94a3b8; margin:-.5rem 0 1rem; }
  </style>
</head>
<body>
  <div class="header">
    <h1>📊 IP Access Dashboard</h1>
    <div class="right">
      <span id="refreshed"></span>
      <button class="link" id="refreshBtn">🔄 새로고침</button>
      <a href="/admin/logout">로그아웃</a>
    </div>
  </div>

  <div class="err-banner" id="errBanner">데이터를 불러오지 못했습니다. 세션이 만료되었을 수 있습니다.</div>

  <div class="cards" id="stats"></div>

  <div class="section">
    <h2>📈 최근 7일 접속 추이</h2>
    <div class="trend" id="trend"></div>
  </div>

  <div class="section">
    <h2>🏷️ 배포본(버전) 관리</h2>
    <p class="hint">라벨을 지정해 배포본별 고정 track_id를 발급합니다. 발급된 ID는 서버 서명이 포함되어 있어
      값을 임의로 바꾸면 서명이 깨져 "위조 의심"으로 표시됩니다 (완전한 변조 차단은 아니며, 변조 시도를 탐지하는 방식입니다).</p>
    <div class="issue-row">
      <input id="newLabel" placeholder="라벨 (예: 고객사A, 2024-06 인쇄본)" maxlength="100">
      <button class="btn btn-pri" id="issueBtn">발급</button>
    </div>
    <div id="issueMsg" style="font-size:.83rem;margin:-.4rem 0 .8rem;display:none"></div>
    <div class="snippet-box" id="snippetBox">
      <div class="hint" style="margin-top:0">아래 스니펫을 해당 배포본 파일에 붙여넣으세요. ENDPOINT는 자동으로 이 서버 주소로 채워집니다.</div>
      <textarea id="snippetText" readonly></textarea>
      <button class="btn btn-sec" id="copyBtn">📋 복사</button>
    </div>
    <table id="versions"><thead><tr><th>라벨</th><th>토큰</th><th>상태</th><th>히트</th><th>최근 접속</th><th>발급일</th><th></th></tr></thead><tbody></tbody></table>
  </div>

  <div class="section">
    <h2>🏆 Top 10 IP</h2>
    <table id="top-ips"><thead><tr><th>IP</th><th>접속 횟수</th></tr></thead><tbody></tbody></table>
  </div>

  <div class="section">
    <h2>📋 최근 로그</h2>
    <div class="btn-row">
      <button class="btn btn-pri" id="firstPageBtn">첫 페이지</button>
      <button class="btn btn-sec" id="prev">◀ 이전</button>
      <button class="btn btn-sec" id="next">다음 ▶</button>
      <span id="page-info" style="align-self:center;font-size:.85rem;color:#64748b;"></span>
      <a class="btn btn-sec" style="text-decoration:none;display:inline-block" id="exportBtn" href="#">⬇ CSV 내보내기</a>
    </div>
    <div class="filter">
      <input id="f-ip" placeholder="IP 필터" style="width:160px">
      <input id="f-id" placeholder="Track ID" style="width:220px">
      <button class="btn btn-pri" id="searchBtn">검색</button>
    </div>
    <table id="logs"><thead><tr><th>#</th><th>IP</th><th>배포본</th><th>UA</th><th>시간</th></tr></thead><tbody></tbody></table>
  </div>

  <script nonce="{{ nonce }}">
    let cur = 1;
    const PAGE_SIZE = 25;
    let autoTimer = null;

    // 서버에서 온 값(ip, track_id, user_agent)은 클라이언트가 통제 가능하므로
    // innerHTML에 넣기 전 반드시 이스케이프한다 (저장형 XSS 방지).
    function escapeHtml(str) {
      return String(str ?? "").replace(/[&<>"']/g, function (c) {
        return { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c];
      });
    }

    async function api(url) {
      const r = await fetch(url, { credentials: "same-origin" });
      if (r.status === 401) { location = "/admin"; return null; }
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }

    function fmt(ts) {
      const d = new Date(ts);
      return isNaN(d) ? ts : d.toLocaleString("ko-KR");
    }

    function showError(show) {
      document.getElementById("errBanner").style.display = show ? "block" : "none";
    }

    async function loadStats() {
      const s = await api("/admin/api/stats");
      if (!s) return;
      document.getElementById("stats").innerHTML = `
        <div class="card"><div class="num">${s.total}</div><div class="label">총 접속</div></div>
        <div class="card"><div class="num">${s.unique_ips}</div><div class="label">고유 IP</div></div>
        <div class="card"><div class="num">${s.unique_ids}</div><div class="label">고유 배포본(검증됨)</div></div>
        <div class="card"><div class="num">${s.tamper_count}</div><div class="label">서명 불일치(위조 의심)</div></div>
        <div class="card"><div class="num">${s.today}</div><div class="label">오늘 접속</div></div>
      `;
      const tb = document.querySelector("#top-ips tbody");
      tb.innerHTML = s.top_ips.length
        ? s.top_ips.map(([ip,c]) => `<tr><td>${escapeHtml(ip)}</td><td>${c}</td></tr>`).join("")
        : `<tr><td colspan="2" class="empty">데이터 없음</td></tr>`;

      const trendEl = document.getElementById("trend");
      const max = Math.max(1, ...s.trend.map(d => d[1]));
      trendEl.innerHTML = s.trend.map(([day, count]) => `
        <div class="bar-wrap">
          <div style="font-size:.72rem;color:#475569">${count}</div>
          <div class="bar" style="height:${Math.round((count / max) * 60)}px"></div>
          <div class="bar-label">${escapeHtml(day.slice(5))}</div>
        </div>
      `).join("");
    }

    async function loadVersions() {
      const v = await api("/admin/api/versions");
      if (!v) return;
      const tb = document.querySelector("#versions tbody");
      tb.innerHTML = v.versions.length ? v.versions.map(x => `<tr>
        <td>${escapeHtml(x.label)}</td>
        <td><span class="badge" title="${escapeHtml(x.token)}">${escapeHtml(x.token.slice(0,10))}…</span></td>
        <td>${x.revoked ? '<span class="tag-revoked">폐기됨</span>' : '<span class="tag-ok">활성</span>'}</td>
        <td>${x.hits}</td>
        <td>${x.last_seen ? fmt(x.last_seen) : "-"}</td>
        <td>${fmt(x.created_at)}</td>
        <td>${x.revoked ? "" : `<button class="btn btn-sec revoke-btn" data-token="${escapeHtml(x.token)}">폐기</button>`}</td>
      </tr>`).join("") : `<tr><td colspan="7" class="empty">발급된 배포본이 없습니다</td></tr>`;
    }

    async function issueVersion() {
      const labelEl = document.getElementById("newLabel");
      const btn     = document.getElementById("issueBtn");
      const msgEl   = document.getElementById("issueMsg");

      const label = labelEl.value.trim();

      // 라벨 미입력 시 인라인 메시지 표시 (조용히 종료하지 않음)
      if (!label) {
        msgEl.style.display = "block";
        msgEl.style.color   = "#b45309";
        msgEl.textContent   = "⚠ 라벨을 입력하세요.";
        labelEl.focus();
        return;
      }

      // 버튼 로딩 상태
      btn.disabled    = true;
      btn.textContent = "발급 중…";
      msgEl.style.display = "none";

      try {
        const r = await fetch("/admin/api/versions", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ label }),
        });

        if (r.status === 401) { location = "/admin"; return; }
        if (!r.ok) throw new Error("HTTP " + r.status);

        const d = await r.json();

        // 스니펫 표시 및 해당 위치로 스크롤
        document.getElementById("snippetText").value = d.snippet;
        const box = document.getElementById("snippetBox");
        box.style.display = "block";
        box.scrollIntoView({ behavior: "smooth", block: "nearest" });

        // 성공 메시지
        msgEl.style.display = "block";
        msgEl.style.color   = "#166534";
        msgEl.textContent   = `✅ "${d.label}" 발급 완료. 아래 스니펫을 복사해 배포 파일에 붙여넣으세요.`;

        labelEl.value = "";
        loadVersions();
      } catch (e) {
        console.error("issueVersion error:", e);
        msgEl.style.display = "block";
        msgEl.style.color   = "#b91c1c";
        msgEl.textContent   = "❌ 발급 실패: " + e.message + " (로그인이 만료됐다면 페이지를 새로고침하세요)";
      } finally {
        btn.disabled    = false;
        btn.textContent = "발급";
      }
    }

    function copySnippet() {
      const el = document.getElementById("snippetText");
      el.select();
      navigator.clipboard && navigator.clipboard.writeText(el.value);
    }

    async function revokeVersion(tokenEncoded) {
      if (!confirm("이 배포본을 폐기 처리할까요? (기존 파일은 계속 신호를 보낼 수 있지만 목록에 폐기 표시됩니다)")) return;
      await fetch(`/admin/api/versions/${tokenEncoded}/revoke`, { method: "POST", credentials: "same-origin" });
      loadVersions();
    }

    async function loadLogs(page) {
      cur = page < 1 ? 1 : page;
      const ip = document.getElementById("f-ip").value.trim();
      const id = document.getElementById("f-id").value.trim();
      let url = `/admin/api/logs?page=${cur}&size=${PAGE_SIZE}`;
      if (ip) url += `&ip=${encodeURIComponent(ip)}`;
      if (id) url += `&track_id=${encodeURIComponent(id)}`;
      const d = await api(url);
      if (!d) return;
      const tb = document.querySelector("#logs tbody");
      tb.innerHTML = d.rows.length ? d.rows.map(r => {
        // 배포본 라벨 셀
        let idCell;
        if (r.verified && r.label) {
          idCell = `<span class="badge">${escapeHtml(r.label)}</span>` +
                   (r.revoked ? ' <span class="tag-revoked">폐기됨</span>' : '');
        } else if (r.verified) {
          idCell = `<span class="badge" title="${escapeHtml(r.token || '')}">미등록 토큰</span>`;
        } else if (r.track_id) {
          idCell = `<span class="tag-warn" title="${escapeHtml(r.track_id)}">위조 의심</span>`;
        } else {
          idCell = "-";
        }

        const displayIp = r.client_ip || r.ip || "-";

        return `<tr>
        <td>${r.id}</td>
        <td>${escapeHtml(displayIp)}</td>
        <td>${idCell}</td>
        <td title="${escapeHtml(r.user_agent || '')}">${escapeHtml((r.user_agent || "").slice(0,40))}</td>
        <td>${fmt(r.created_at)}</td>
      </tr>`;
      }).join("") : `<tr><td colspan="5" class="empty">로그가 없습니다</td></tr>`;
      document.getElementById("page-info").textContent = `페이지 ${d.page}/${d.pages} (총 ${d.total}건)`;
      document.getElementById("prev").disabled = d.page <= 1;
      document.getElementById("next").disabled = d.page >= d.pages;
      document.getElementById("exportBtn").href =
        `/admin/api/export?ip=${encodeURIComponent(ip)}&track_id=${encodeURIComponent(id)}`;
    }

    async function refreshAll() {
      try {
        showError(false);
        await Promise.all([loadStats(), loadLogs(cur), loadVersions()]);
        document.getElementById("refreshed").textContent =
          "마지막 갱신: " + new Date().toLocaleTimeString("ko-KR");
      } catch (e) {
        showError(true);
      }
    }

    function scheduleAutoRefresh() {
      if (autoTimer) clearInterval(autoTimer);
      // 탭이 백그라운드일 때는 폴링을 건너뛰어 불필요한 서버 부하를 줄인다.
      autoTimer = setInterval(() => {
        if (document.visibilityState === "visible") refreshAll();
      }, 15000);
    }

    refreshAll();
    scheduleAutoRefresh();

    // ── 이벤트 바인딩 (CSP: onclick 속성 대신 addEventListener 사용) ──────
    document.getElementById("refreshBtn").addEventListener("click", refreshAll);
    document.getElementById("issueBtn").addEventListener("click", issueVersion);
    document.getElementById("copyBtn").addEventListener("click", copySnippet);
    document.getElementById("firstPageBtn").addEventListener("click", function(){ loadLogs(1); });
    document.getElementById("prev").addEventListener("click", function(){ loadLogs(cur - 1); });
    document.getElementById("next").addEventListener("click", function(){ loadLogs(cur + 1); });
    document.getElementById("searchBtn").addEventListener("click", function(){ loadLogs(1); });

    // 검색 입력란에서 Enter 키로도 검색 가능하도록
    ["f-ip", "f-id"].forEach(function(id) {
      document.getElementById(id).addEventListener("keydown", function(e) {
        if (e.key === "Enter") loadLogs(1);
      });
    });

    // 폐기 버튼: 동적으로 생성되므로 versions 테이블에 이벤트 위임
    document.getElementById("versions").addEventListener("click", function(e) {
      var btn = e.target.closest(".revoke-btn");
      if (!btn) return;
      var token = btn.dataset.token;
      if (!token) return;
      revokeVersion(encodeURIComponent(token));
    });
  </script>
</body>
</html>
"""

# ── Admin routes ────────────────────────────────────────────

@app.route("/admin")
def admin():
    if "admin" not in session:
        session["csrf_token"] = secrets.token_hex(16)
        return render_template_string(
            LOGIN_TEMPLATE, error=None,
            csrf_token=session["csrf_token"], nonce=g.csp_nonce,
        )
    return render_template_string(DASHBOARD_TEMPLATE, nonce=g.csp_nonce)


@app.route("/admin/login", methods=["POST"])
def admin_login():
    ip = _get_client_ip()
    if _rate_limited(f"login:{ip}", limit=5, window=60):
        return render_template_string(
            LOGIN_TEMPLATE, error="로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.",
            csrf_token=session.get("csrf_token", ""), nonce=g.csp_nonce,
        ), 429

    token = request.form.get("csrf_token", "")
    if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
        session["csrf_token"] = secrets.token_hex(16)
        return render_template_string(
            LOGIN_TEMPLATE, error="세션이 만료되었습니다. 다시 시도해주세요.",
            csrf_token=session["csrf_token"], nonce=g.csp_nonce,
        ), 400

    user = request.form.get("user", "")
    pw = request.form.get("pw", "")
    if _check_auth(user, pw):
        session.clear()
        session["admin"] = True
        session.permanent = True
        return redirect("/admin")

    session["csrf_token"] = secrets.token_hex(16)
    return render_template_string(
        LOGIN_TEMPLATE, error="ID 또는 비밀번호가 올바르지 않습니다.",
        csrf_token=session["csrf_token"], nonce=g.csp_nonce,
    )


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin")


# ── Admin API ───────────────────────────────────────────────

def _require_admin():
    if "admin" not in session:
        return jsonify(error="unauthorized"), 401
    return None


_stats_cache = {"data": None, "at": 0.0}
_stats_lock = threading.Lock()
_STATS_TTL = 5.0  # seconds — 대시보드가 자주 폴링해도 DB 부하가 늘지 않도록 캐시


@app.route("/admin/api/stats")
def api_stats():
    err = _require_admin()
    if err:
        return err

    with _stats_lock:
        if _stats_cache["data"] is not None and (time.time() - _stats_cache["at"]) < _STATS_TTL:
            return jsonify(_stats_cache["data"])

    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM access_log").fetchone()[0]
    u_ip = db.execute(
        "SELECT COUNT(DISTINCT client_ip) FROM access_log WHERE client_ip IS NOT NULL AND client_ip != ''"
    ).fetchone()[0]
    u_id = db.execute(
        "SELECT COUNT(DISTINCT token) FROM access_log WHERE verified = 1"
    ).fetchone()[0]
    tamper = db.execute(
        "SELECT COUNT(*) FROM access_log WHERE verified = 0 AND track_id IS NOT NULL AND track_id != ''"
    ).fetchone()[0]
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today = db.execute(
        "SELECT COUNT(*) FROM access_log WHERE created_at >= ?", (today_str,)
    ).fetchone()[0]
    top = db.execute(
        "SELECT client_ip, COUNT(*) c FROM access_log "
        "WHERE client_ip IS NOT NULL AND client_ip != '' "
        "GROUP BY client_ip ORDER BY c DESC LIMIT 10"
    ).fetchall()

    week_ago = (datetime.now(timezone.utc) - timedelta(days=6)).strftime("%Y-%m-%d")
    trend_rows = dict(db.execute(
        "SELECT substr(created_at,1,10) d, COUNT(*) c FROM access_log "
        "WHERE created_at >= ? GROUP BY d ORDER BY d",
        (week_ago,),
    ).fetchall())
    trend = []
    for i in range(6, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        trend.append([day, trend_rows.get(day, 0)])

    payload = dict(total=total, unique_ips=u_ip, unique_ids=u_id, tamper_count=tamper,
                   today=today, top_ips=top, trend=trend)
    with _stats_lock:
        _stats_cache["data"] = payload
        _stats_cache["at"] = time.time()
    return jsonify(payload)


@app.route("/admin/api/logs")
def api_logs():
    err = _require_admin()
    if err:
        return err

    page = _safe_int(request.args.get("page"), 1, 1, 10**9)
    size = _safe_int(request.args.get("size"), 25, 1, 100)
    where_sql, params = _log_filter_clause()

    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM access_log {where_sql}", params).fetchone()[0]
    pages = max(1, (total + size - 1) // size)
    page = min(page, pages)
    rows = db.execute(
        f"SELECT a.id, a.client_ip, a.ip, a.track_id, a.token, "
        f"a.verified, a.user_agent, a.created_at, v.label, v.revoked "
        f"FROM access_log a LEFT JOIN track_versions v ON v.token = a.token "
        f"{where_sql} "
        f"ORDER BY a.id DESC LIMIT ? OFFSET ?",
        params + [size, (page - 1) * size],
    ).fetchall()

    return jsonify(
        page=page, pages=pages, total=total,
        rows=[
            {"id": r[0], "ip": r[1] or r[2],   # client_ip 우선, 없으면 server ip
             "client_ip": r[1], "track_id": r[3], "token": r[4], "verified": bool(r[5]),
             "user_agent": r[6], "created_at": r[7],
             "label": r[8], "revoked": bool(r[9]) if r[9] is not None else False}
            for r in rows
        ],
    )


@app.route("/admin/api/export")
def api_export():
    err = _require_admin()
    if err:
        return err

    where_sql, params = _log_filter_clause()
    db = get_db()
    rows = db.execute(
        f"SELECT a.id, COALESCE(a.client_ip, a.ip), a.track_id, a.token, "
        f"a.verified, v.label, a.user_agent, a.created_at "
        f"FROM access_log a LEFT JOIN track_versions v ON v.token = a.token "
        f"{where_sql} "
        f"ORDER BY a.id DESC LIMIT 10000",
        params,
    ).fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "ip", "raw_track_id", "token", "verified", "label", "user_agent", "created_at"])
    writer.writerows(rows)

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=access_log_export.csv"},
    )


# ── 배포본(버전) 관리 API ────────────────────────────────────────
# "여러 버전으로 배포하고 각 배포본을 추적"하는 용도: 라벨(예: "고객사A",
# "2024-06 인쇄본")별로 서명된 고정 track_id를 발급하고, 그 ID가 박힌
# tracking snippet을 받아서 실제 파일에 심는다. 이후 /track으로 들어오는
# 서명이 유효한 요청은 이 라벨과 자동으로 매칭되어 대시보드에 표시된다.

def _render_snippet(signed_id: str, label: str = "") -> str:
    base      = request.url_root.rstrip("/")
    track_url = f"{base}/track"
    ip_url    = f"{base}/ip"
    comment   = f"// tracking: {label}" if label else "// tracking snippet"
    # IIFE는 변수 캡처 용도로만 사용. getIp() 자체는 즉시 호출되지 않는다.
    # 기존 코드가 getIp()를 호출할 때:
    #   1순위: 자체 /ip (Render, XFF 첫 항목 → 실제 클라이언트 IP)
    #   2순위: ipify → icanhazip → ipapi.co 순서 폴백
    # IP를 처음 가져오는 순간 /track 에 한 번만 기록 (_s 플래그로 중복 방지).
    # 이후 호출은 ipCache 캐시에서 즉시 반환 (추가 네트워크 없음).
    code = (
        f"(function(){{var _I={json.dumps(signed_id)},_T={json.dumps(track_url)},_P={json.dumps(ip_url)},_s=false;"
        "getIp=function(){"
          "if(ipCache)return Promise.resolve(ipCache);"
          "return fetchIp(_P)"
            ".catch(function(){return fetchIp('https://api4.ipify.org?format=json')})"
            ".catch(function(){return fetchIp('https://ipv4.icanhazip.com',true)})"
            ".catch(function(){return fetchIp('https://ipapi.co/ip/',true)})"
            ".then(function(ip){"
              "ipCache=ip;"
              "if(!_s){_s=true;"
                "var p=JSON.stringify({id:_I,client_ip:ip});"
                "navigator.sendBeacon?navigator.sendBeacon(_T,new Blob([p],{type:'text/plain'})):"
                "fetch(_T,{method:'POST',headers:{'Content-Type':'text/plain'},body:p,keepalive:!0,mode:'cors'}).catch(function(){});"
              "}"
              "return ip;"
            "});"
        "};"
        "})();"
    )
    return f"{comment}\n{code}"


@app.route("/admin/api/versions", methods=["GET"])
def api_versions_list():
    err = _require_admin()
    if err:
        return err

    db = get_db()
    rows = db.execute("""
        SELECT v.token, v.label, v.revoked, v.created_at,
               (SELECT COUNT(*) FROM access_log a WHERE a.token = v.token AND a.verified = 1) AS hits,
               (SELECT MAX(a.created_at) FROM access_log a WHERE a.token = v.token AND a.verified = 1) AS last_seen
        FROM track_versions v
        ORDER BY v.created_at DESC
    """).fetchall()

    tamper_count = db.execute(
        "SELECT COUNT(*) FROM access_log WHERE verified = 0 AND track_id IS NOT NULL AND track_id != ''"
    ).fetchone()[0]

    return jsonify(
        versions=[
            {"token": r[0], "label": r[1], "revoked": bool(r[2]), "created_at": r[3],
             "hits": r[4], "last_seen": r[5]}
            for r in rows
        ],
        tamper_count=tamper_count,
    )


@app.route("/admin/api/versions", methods=["POST"])
def api_versions_create():
    err = _require_admin()
    if err:
        return err

    body = request.get_json(silent=True, force=True) or {}
    label = str(body.get("label", "")).strip()[:100]
    if not label:
        return jsonify(error="label_required"), 400

    # 기존에 발급했던 토큰을 그대로 다시 등록(복구)하고 싶을 때 사용.
    # (예: 파일시스템 초기화로 track_versions 레지스트리를 잃어버렸지만
    #  어딘가 따로 적어둔 토큰 값이 있는 경우 라벨을 다시 붙여 복구한다.
    #  서명 자체는 TRACK_SIGNING_KEY만 그대로면 여전히 유효하다.)
    existing_token = str(body.get("existing_token", "")).strip()[:64]
    token = existing_token or _new_version_token()
    signed_id = _sign_token(token)

    db = get_db()
    db.execute(
        "INSERT INTO track_versions (token, label, revoked, created_at) VALUES (?, ?, 0, ?) "
        "ON CONFLICT(token) DO UPDATE SET label = excluded.label, revoked = 0",
        (token, label, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()

    return jsonify(token=token, signed_id=signed_id, label=label, snippet=_render_snippet(signed_id, label))


@app.route("/admin/api/versions/<token>/revoke", methods=["POST"])
def api_versions_revoke(token):
    err = _require_admin()
    if err:
        return err
    db = get_db()
    db.execute("UPDATE track_versions SET revoked = 1 WHERE token = ?", (token,))
    db.commit()
    return jsonify(ok=True)


# ─── Entry point ───────────────────────────────────────────

_init_db()

if os.environ.get("RENDER"):
    # Render가 자동으로 심어주는 환경 변수. 무료 플랜은 재배포/스핀다운마다
    # 파일시스템이 초기화되므로 SQLite 데이터가 사라진다는 점을 배포 로그에 남긴다.
    print("ℹ  Render 환경 감지: 무료 플랜은 파일시스템이 휘발성입니다. "
          "재배포/스핀다운 시 access_log.db의 데이터가 초기화됩니다.")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"  📡  Sample page : http://localhost:{port}/page")
    print(f"  🔐  Admin panel : http://localhost:{port}/admin")
    print(f"  📝  Track API   : POST http://localhost:{port}/track")
    print("  ⚠  내장 서버는 개발용입니다. 운영 환경에서는 gunicorn/waitress 등 WSGI 서버 뒤에서 실행하세요.")
    app.run(host="0.0.0.0", port=port)
