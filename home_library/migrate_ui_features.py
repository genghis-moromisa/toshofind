import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "library.db"

def column_exists(cur, table: str, col: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == col for row in cur.fetchall())

def table_exists(cur, table: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None

def main():
    if not DB_PATH.exists():
        raise SystemExit(f"DB not found: {DB_PATH}")

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # 1) books.status を追加（未読をデフォルト）
    if not column_exists(cur, "books", "status"):
        cur.execute("ALTER TABLE books ADD COLUMN status TEXT NOT NULL DEFAULT '未読'")
        print("Added column: books.status")
    else:
        print("books.status already exists")

    # 2) 場所履歴テーブルを追加
    # ※ user_id が books にある前提（あなたはB達成と言っているので）
    if not table_exists(cur, "book_locations"):
        cur.execute("""
        CREATE TABLE book_locations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          book_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          location TEXT NOT NULL,
          changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(book_id) REFERENCES books(id)
        )
        """)
        cur.execute("CREATE INDEX idx_book_locations_book ON book_locations(book_id)")
        cur.execute("CREATE INDEX idx_book_locations_user ON book_locations(user_id)")
        print("Created table: book_locations")
    else:
        print("book_locations already exists")

    con.commit()
    con.close()
    print("Migration complete.")

if __name__ == "__main__":
    main()
