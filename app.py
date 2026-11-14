
import os
import sqlite3
import secrets
from pathlib import Path
from functools import wraps
from datetime import timedelta

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort, g
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("NOVA_SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError("NOVA_SECRET_KEY must be at least 32 characters.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    DATABASE=str(INSTANCE_DIR / "nova_academy.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=1024 * 1024
)

CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    return response


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(category_id)
                REFERENCES categories(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_posts_category
        ON posts(category_id);
    """)

    default_categories = [
        "Cybersecurity",
        "Linux",
        "Programming Languages",
        "Graphic Design",
        "Types of Hackers",
        "Cybersecurity Careers"
    ]

    for name in default_categories:
        db.execute(
            "INSERT OR IGNORE INTO categories(name) VALUES (?)",
            (name,)
        )

    db.commit()


@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Database initialized.")


@app.cli.command("create-admin")
def create_admin_command():
    init_db()
    username = input("Admin username: ").strip()
    password = input("Admin password: ")

    if len(username) < 3 or len(password) < 12:
        print("Username must be 3+ characters and password 12+ characters.")
        return

    db = get_db()
    try:
        db.execute(
            "INSERT INTO admins(username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        db.commit()
        print("Admin created.")
    except sqlite3.IntegrityError:
        print("Username already exists.")


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if not session.get("admin_id"):
            flash("تکایە سەرەتا بچۆ ژوورەوە.")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped_view


@app.route("/")
def index():
    db = get_db()
    categories = db.execute(
        "SELECT * FROM categories ORDER BY id ASC"
    ).fetchall()
    return render_template("index.html", categories=categories)


@app.route("/category/<int:category_id>")
def category(category_id):
    db = get_db()
    selected = db.execute(
        "SELECT * FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if selected is None:
        abort(404)

    posts = db.execute(
        "SELECT * FROM posts WHERE category_id = ? ORDER BY id DESC",
        (category_id,)
    ).fetchall()
    return render_template("category.html", category=selected, posts=posts)


@app.route("/post/<int:post_id>")
def post(post_id):
    db = get_db()
    selected = db.execute("""
        SELECT posts.*, categories.name AS category_name,
               categories.id AS category_id
        FROM posts
        JOIN categories ON categories.id = posts.category_id
        WHERE posts.id = ?
    """, (post_id,)).fetchone()

    if selected is None:
        abort(404)
    return render_template("post.html", post=selected)


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    results = []
    if query:
        db = get_db()
        results = db.execute("""
            SELECT posts.*, categories.name AS category_name
            FROM posts
            JOIN categories ON categories.id = posts.category_id
            WHERE posts.title LIKE ? OR posts.content LIKE ?
            ORDER BY posts.id DESC
        """, (f"%{query}%", f"%{query}%")).fetchall()

    return render_template("search.html", query=query, results=results)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if session.get("admin_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()

        admin = db.execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()

        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            session.permanent = True
            flash("بە سەرکەوتوویی چوویتە ژوورەوە.")
            return redirect(url_for("dashboard"))

        flash("ناوی بەکارهێنەر یان وشەی نهێنی هەڵەیە.")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@admin_required
def logout():
    session.clear()
    flash("بە سەرکەوتوویی دەرچوویت.")
    return redirect(url_for("index"))


@app.route("/dashboard")
@admin_required
def dashboard():
    db = get_db()
    categories = db.execute(
        "SELECT * FROM categories ORDER BY id DESC"
    ).fetchall()
    posts = db.execute("""
        SELECT posts.*, categories.name AS category_name
        FROM posts JOIN categories ON categories.id = posts.category_id
        ORDER BY posts.id DESC
    """).fetchall()
    return render_template(
        "dashboard.html", categories=categories, posts=posts
    )


@app.route("/dashboard/category/new", methods=["GET", "POST"])
@admin_required
def new_category():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name or len(name) > 80:
            flash("ناوی بەشەکە دروست نییە.")
            return redirect(url_for("new_category"))

        db = get_db()
        try:
            db.execute("INSERT INTO categories(name) VALUES (?)", (name,))
            db.commit()
            flash("بەشەکە زیاد کرا.")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("ئەم ناوە پێشتر هەیە.")

    return render_template("category_form.html", category=None)


@app.route("/dashboard/category/<int:category_id>/edit",
           methods=["GET", "POST"])
@admin_required
def edit_category(category_id):
    db = get_db()
    selected = db.execute(
        "SELECT * FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if selected is None:
        abort(404)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name or len(name) > 80:
            flash("ناوی بەشەکە دروست نییە.")
            return redirect(url_for("edit_category", category_id=category_id))
        try:
            db.execute(
                "UPDATE categories SET name = ? WHERE id = ?",
                (name, category_id)
            )
            db.commit()
            flash("ناوی بەشەکە گۆڕدرا.")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("ئەم ناوە پێشتر هەیە.")

    return render_template("category_form.html", category=selected)


@app.route("/dashboard/category/<int:category_id>/delete", methods=["POST"])
@admin_required
def delete_category(category_id):
    db = get_db()
    selected = db.execute(
        "SELECT id FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if selected is None:
        abort(404)
    db.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    db.commit()
    flash("بەشەکە و وانەکانی ناوی سڕانەوە.")
    return redirect(url_for("dashboard"))


@app.route("/dashboard/post/new", methods=["GET", "POST"])
@admin_required
def new_post():
    db = get_db()
    categories = db.execute(
        "SELECT * FROM categories ORDER BY name"
    ).fetchall()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        category_id = request.form.get("category_id", "").strip()

        if (not title or len(title) > 200 or not content
                or len(content) > 100000 or not category_id.isdigit()):
            flash("تکایە زانیارییەکان بە دروستی پڕ بکەرەوە.")
            return redirect(url_for("new_post"))

        exists = db.execute(
            "SELECT id FROM categories WHERE id = ?", (int(category_id),)
        ).fetchone()
        if exists is None:
            abort(400)

        db.execute("""
            INSERT INTO posts(category_id, title, content)
            VALUES (?, ?, ?)
        """, (int(category_id), title, content))
        db.commit()
        flash("وانەکە زیاد کرا.")
        return redirect(url_for("dashboard"))

    return render_template("post_form.html", post=None, categories=categories)


@app.route("/dashboard/post/<int:post_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    db = get_db()
    selected = db.execute(
        "SELECT * FROM posts WHERE id = ?", (post_id,)
    ).fetchone()
    if selected is None:
        abort(404)

    categories = db.execute(
        "SELECT * FROM categories ORDER BY name"
    ).fetchall()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        category_id = request.form.get("category_id", "").strip()

        if (not title or len(title) > 200 or not content
                or len(content) > 100000 or not category_id.isdigit()):
            flash("تکایە زانیارییەکان بە دروستی پڕ بکەرەوە.")
            return redirect(url_for("edit_post", post_id=post_id))

        exists = db.execute(
            "SELECT id FROM categories WHERE id = ?", (int(category_id),)
        ).fetchone()
        if exists is None:
            abort(400)

        db.execute("""
            UPDATE posts
            SET title = ?, content = ?, category_id = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (title, content, int(category_id), post_id))
        db.commit()
        flash("وانەکە نوێ کرایەوە.")
        return redirect(url_for("dashboard"))

    return render_template(
        "post_form.html", post=selected, categories=categories
    )


@app.route("/dashboard/post/<int:post_id>/delete", methods=["POST"])
@admin_required
def delete_post(post_id):
    db = get_db()
    selected = db.execute(
        "SELECT id FROM posts WHERE id = ?", (post_id,)
    ).fetchone()
    if selected is None:
        abort(404)

    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    flash("وانەکە سڕایەوە.")
    return redirect(url_for("dashboard"))


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(413)
def request_too_large(error):
    return "قەبارەی داواکارییەکە زۆر گەورەیە.", 413


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
