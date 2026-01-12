import os
import json
import sqlite3
import secrets
import functools
import urllib.request
import urllib.parse
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, g, render_template, request, redirect, url_for,
    session, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash


# =========================================================
# App config
# =========================================================
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DB_PATH") or (BASE_DIR / "library.db"))


app = Flask(__name__)
# 本番では必ず環境変数で固定してください（毎回変わるとログインが飛びます）
app.secret_key = os.environ.get("APP_SECRET") or secrets.token_urlsafe(48)


# =========================================================
# DB helpers
# =========================================================
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        g.db = con
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def column_exists(cur: sqlite3.Cursor, table: str, col: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(r["name"] == col for r in cur.fetchall())


def table_exists(cur: sqlite3.Cursor, table: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None


def init_db_and_migrate():
    """
    既存DBがあっても壊さず、足りないテーブル/カラムだけを補います。
    """
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    cur = db.cursor()

    # users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # books（ユーザー分離 + status + メタデータ）
    cur.execute("""
    CREATE TABLE IF NOT EXISTS books (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      isbn TEXT,
      title TEXT NOT NULL,
      authors TEXT,
      tags TEXT,
      location TEXT,
      notes TEXT,
      status TEXT NOT NULL DEFAULT '未読',
      cover_url TEXT,
      source TEXT,
      meta_json TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # 既存DB向け：足りないカラムを追加
    # （すでに存在するなら何もしません）
    # user_id
    if not column_exists(cur, "books", "user_id"):
        # 既存DBに user_id がない場合の救済：後で admin に紐付けます
        cur.execute("ALTER TABLE books ADD COLUMN user_id INTEGER")
    # status
    if not column_exists(cur, "books", "status"):
        cur.execute("ALTER TABLE books ADD COLUMN status TEXT NOT NULL DEFAULT '未読'")
    # cover_url
    if not column_exists(cur, "books", "cover_url"):
        cur.execute("ALTER TABLE books ADD COLUMN cover_url TEXT")
    # source
    if not column_exists(cur, "books", "source"):
        cur.execute("ALTER TABLE books ADD COLUMN source TEXT")
    # meta_json
    if not column_exists(cur, "books", "meta_json"):
        cur.execute("ALTER TABLE books ADD COLUMN meta_json TEXT")
    # created_at / updated_at
    if not column_exists(cur, "books", "created_at"):
        cur.execute("ALTER TABLE books ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")
    if not column_exists(cur, "books", "updated_at"):
        cur.execute("ALTER TABLE books ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")

    # 場所履歴
    if not table_exists(cur, "book_locations"):
        cur.execute("""
        CREATE TABLE book_locations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          book_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          location TEXT NOT NULL,
          changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(book_id) REFERENCES books(id),
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_book_locations_book ON book_locations(book_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_book_locations_user ON book_locations(user_id)")

    db.commit()

    # 既存DBで user_id がNULLの場合、admin に寄せる（安全側の補正）
    cur.execute("SELECT id FROM users WHERE username=?", ("admin",))
    admin = cur.fetchone()
    if admin:
        admin_id = admin["id"]
        # user_idがNULLの本をadminに紐付け
        cur.execute("UPDATE books SET user_id=? WHERE user_id IS NULL", (admin_id,))
        db.commit()

    db.close()


# 起動時にマイグレーション
init_db_and_migrate()


# =========================================================
# Security: CSRF
# =========================================================
def get_csrf() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["csrf_token"] = tok
    return tok


def require_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or sent != session.get("csrf_token"):
            abort(400, description="Bad CSRF token")


@app.before_request
def _csrf_guard():
    # GET等は対象外、POSTのみ
    if request.method == "POST":
        require_csrf()


@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf()}


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


# =========================================================
# Auth routes
# =========================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("ユーザー名とパスワードは必須です。")
            return render_template("register.html", title="新規登録")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users(username, password_hash) VALUES(?, ?)",
                (username, generate_password_hash(password))
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("そのユーザー名は既に使われています。")
            return render_template("register.html", title="新規登録")

        # 自動ログイン
        row = db.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        get_csrf()  # token確保
        flash("登録しました。")
        return redirect(url_for("index"))

    return render_template("register.html", title="新規登録")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("ユーザー名またはパスワードが違います。")
            return render_template("login.html", title="ログイン")

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        get_csrf()
        flash("ログインしました。")
        return redirect(url_for("index"))

    return render_template("login.html", title="ログイン")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("ログアウトしました。")
    return redirect(url_for("login"))


# =========================================================
# Books: list / add / detail / edit
# =========================================================
@app.route("/", methods=["GET"])
@login_required
def index():
    user_id = session["user_id"]
    q = (request.args.get("q") or "").strip()

    db = get_db()
    if q:
        like = f"%{q}%"
        rows = db.execute(
            """
            SELECT * FROM books
            WHERE user_id=?
              AND (
                title LIKE ?
                OR authors LIKE ?
                OR tags LIKE ?
                OR isbn LIKE ?
              )
            ORDER BY updated_at DESC, id DESC
            """,
            (user_id, like, like, like, like),
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT * FROM books
            WHERE user_id=?
            ORDER BY updated_at DESC, id DESC
            """,
            (user_id,),
        ).fetchall()

    return render_template("index.html", books=rows, q=q, title="蔵書一覧")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    user_id = session["user_id"]

    prefill = {
        "isbn": request.args.get("isbn", "") or "",
        "title": "",
        "authors": "",
        "tags": "",
        "location": "",
        "notes": "",
        "status": "未読",
    }

    if request.method == "POST":
        isbn = (request.form.get("isbn") or "").strip()
        title = (request.form.get("title") or "").strip()
        authors = (request.form.get("authors") or "").strip()
        tags = (request.form.get("tags") or "").strip()
        location = (request.form.get("location") or "").strip()
        notes = (request.form.get("notes") or "").strip()
        status = (request.form.get("status") or "未読").strip() or "未読"

        if not title:
            flash("タイトルは必須です。")
            prefill.update(
                isbn=isbn, title=title, authors=authors, tags=tags,
                location=location, notes=notes, status=status
            )
            return render_template("add.html", prefill=prefill, title="手動追加")

        db = get_db()
        db.execute(
            """
            INSERT INTO books(user_id, isbn, title, authors, tags, location, notes, status, updated_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (user_id, isbn or None, title, authors or None, tags or None, location or None, notes or None, status),
        )
        db.commit()
        flash("追加しました。")
        return redirect(url_for("index"))

    return render_template("add.html", prefill=prefill, title="手動追加")


@app.route("/book/<int:book_id>", methods=["GET"])
@login_required
def book(book_id: int):
    user_id = session["user_id"]
    db = get_db()

    b_row = db.execute(
        "SELECT * FROM books WHERE id=? AND user_id=?",
        (book_id, user_id)
    ).fetchone()
    if not b_row:
        abort(404)

    b = dict(b_row)  # ★ これが重要

    history_rows = db.execute(
        """
        SELECT location, changed_at
        FROM book_locations
        WHERE book_id=? AND user_id=?
        ORDER BY changed_at DESC, id DESC
        LIMIT 50
        """,
        (book_id, user_id)
    ).fetchall()
    history = [dict(r) for r in history_rows]  # ★ 念のため

    return render_template("book.html", b=b, history=history, title="詳細")


@app.route("/edit/<int:book_id>", methods=["GET", "POST"])
@login_required
def edit(book_id: int):
    user_id = session["user_id"]
    db = get_db()

    b_row = db.execute(
        "SELECT * FROM books WHERE id=? AND user_id=?",
        (book_id, user_id)
    ).fetchone()
    if not b_row:
        abort(404)

    b = dict(b_row)  # ★ これが重要（テンプレで b.get() が使えるようになる）

    if request.method == "POST":
        old_location = (b.get("location") or "").strip()

        isbn = (request.form.get("isbn") or "").strip()
        title = (request.form.get("title") or "").strip()
        authors = (request.form.get("authors") or "").strip()
        tags = (request.form.get("tags") or "").strip()
        location = (request.form.get("location") or "").strip()
        notes = (request.form.get("notes") or "").strip()
        status = (request.form.get("status") or "未読").strip() or "未読"

        if not title:
            flash("タイトルは必須です。")
            b.update(
                isbn=isbn, title=title, authors=authors, tags=tags,
                location=location, notes=notes, status=status
            )
            return render_template("edit.html", b=b, title="簡易編集")

        db.execute(
            """
            UPDATE books
            SET isbn=?, title=?, authors=?, tags=?, location=?, notes=?, status=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND user_id=?
            """,
            (isbn or None, title, authors or None, tags or None, location or None, notes or None, status, book_id, user_id)
        )

        new_location = location.strip()
        if new_location and new_location != old_location:
            db.execute(
                "INSERT INTO book_locations(book_id, user_id, location) VALUES(?, ?, ?)",
                (book_id, user_id, new_location)
            )

        db.commit()
        flash("保存しました。")
        return redirect(url_for("book", book_id=book_id))

    return render_template("edit.html", b=b, title="簡易編集")

    db.execute(
            """
            UPDATE books
            SET isbn=?, title=?, authors=?, tags=?, location=?, notes=?, status=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND user_id=?
            """,
            (isbn or None, title, authors or None, tags or None, location or None, notes or None, status, book_id, user_id)
        )

        # 場所履歴：変化したときだけ記録（新しいlocationが空なら記録しない）
    new_location = location.strip()
    if new_location and new_location != old_location:
            db.execute(
                "INSERT INTO book_locations(book_id, user_id, location) VALUES(?, ?, ?)",
                (book_id, user_id, new_location)
            )

    db.commit()
    flash("保存しました。")
    return redirect(url_for("book", book_id=book_id))

    return render_template("edit.html", b=b, title="簡易編集")


# =========================================================
# Scan routes (iPhone shortcut)
# =========================================================
@app.route("/scan", methods=["GET"])
@login_required
def scan():
    user_id = session["user_id"]
    code = (request.args.get("code") or "").strip()
    found = None
    if code:
        db = get_db()
        found = db.execute(
            "SELECT * FROM books WHERE user_id=? AND isbn=?",
            (user_id, code)
        ).fetchone()

    return render_template("scan.html", code=code, found=found, title="スキャン")


def _http_get_json(url: str, timeout: int = 7):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "home-library/1.0 (+https://example.invalid)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read().decode("utf-8")
        return json.loads(data)


def fetch_book_metadata_by_isbn(isbn: str):
    """
    OpenLibrary → ダメならGoogle Books。
    返す dict には title/authors/cover_url/source/meta_json を入れる。
    """
    isbn = isbn.replace("-", "").strip()
    if not isbn:
        return None

    # 1) OpenLibrary
    try:
        ol_url = f"https://openlibrary.org/isbn/{urllib.parse.quote(isbn)}.json"
        ol = _http_get_json(ol_url)
        title = (ol.get("title") or "").strip()

        authors_list = []
        for a in (ol.get("authors") or []):
            key = a.get("key")
            if key:
                try:
                    ad = _http_get_json(f"https://openlibrary.org{key}.json")
                    name = (ad.get("name") or "").strip()
                    if name:
                        authors_list.append(name)
                except Exception:
                    pass

        cover_url = f"https://covers.openlibrary.org/b/isbn/{isbn}-L.jpg"

        if title:
            return {
                "isbn": isbn,
                "title": title,
                "authors": ", ".join(authors_list) if authors_list else "",
                "cover_url": cover_url,
                "source": "openlibrary",
                "meta_json": json.dumps(ol, ensure_ascii=False),
            }
    except Exception:
        pass

    # 2) Google Books
    try:
        gb_url = "https://www.googleapis.com/books/v1/volumes?q=" + urllib.parse.quote(f"isbn:{isbn}")
        gb = _http_get_json(gb_url)
        items = gb.get("items") or []
        if items:
            vi = (items[0].get("volumeInfo") or {})
            title = (vi.get("title") or "").strip()
            authors = vi.get("authors") or []
            image_links = vi.get("imageLinks") or {}
            cover_url = image_links.get("thumbnail") or image_links.get("smallThumbnail") or ""

            if title:
                return {
                    "isbn": isbn,
                    "title": title,
                    "authors": ", ".join(authors) if authors else "",
                    "cover_url": cover_url,
                    "source": "googlebooks",
                    "meta_json": json.dumps(items[0], ensure_ascii=False),
                }
    except Exception:
        pass

    return None


@app.route("/scan_auto_add", methods=["GET"])
@login_required
def scan_auto_add():
    """
    /scan_auto_add?code=978... でISBNを受け取り、メタデータ取得して追加。
    失敗なら /add?isbn=... に回す。
    """
    user_id = session["user_id"]
    code = (request.args.get("code") or "").strip()

    if not code:
        flash("code がありません。")
        return redirect(url_for("scan"))

    db = get_db()

    # 既に登録済みなら詳細へ
    ex = db.execute(
        "SELECT id FROM books WHERE user_id=? AND isbn=?",
        (user_id, code)
    ).fetchone()
    if ex:
        flash("既に登録済みです。")
        return redirect(url_for("book", book_id=ex["id"]))

    meta = fetch_book_metadata_by_isbn(code)
    if not meta or not meta.get("title"):
        flash("自動取得に失敗しました。手動追加へ進みます。")
        return redirect(url_for("add", isbn=code))

    db.execute(
        """
        INSERT INTO books(user_id, isbn, title, authors, status, cover_url, source, meta_json, updated_at)
        VALUES(?, ?, ?, ?, '未読', ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            user_id,
            meta.get("isbn") or code,
            meta.get("title"),
            meta.get("authors") or None,
            meta.get("cover_url") or None,
            meta.get("source") or None,
            meta.get("meta_json") or None,
        )
    )
    db.commit()

    new_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    flash("自動取得して追加しました。")
    return redirect(url_for("book", book_id=new_id))


# =========================================================
# (Optional) Health check
# =========================================================
@app.route("/health")
def health():
    return {"ok": True, "time": datetime.utcnow().isoformat() + "Z"}


if __name__ == "__main__":
    # 本番では debug=False で運用してください
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
