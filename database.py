import sqlite3

TABLE_NAME = 'ids'


class Database:

    def __init__(self, db_file_path) -> None:
        self.conn = sqlite3.connect(db_file_path)
        self.cursor = self.conn.cursor()
        self.cursor.execute(f"CREATE TABLE IF NOT EXISTS {TABLE_NAME} (id INTEGER PRIMARY KEY)")

    def __del__(self):
        self.cursor.close()
        self.conn.close()

    def add_if_not_contains(self, id):
        if not self.contains(id):
            self.cursor.execute(f"INSERT INTO {TABLE_NAME} VALUES (?)", (id,))
        self.conn.commit()

    def delete(self, id):
        self.cursor.execute(f"DELETE FROM {TABLE_NAME} WHERE id=?", (id,))
        self.conn.commit()

    def contains(self, id):
        self.cursor.execute(f"SELECT * FROM {TABLE_NAME} WHERE id=?", (id,))
        return self.cursor.fetchone() is not None
