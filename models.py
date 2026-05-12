from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from bcrypt import gensalt, hashpw, checkpw

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='vendedor')  # admin, vendedor, bodega

    def set_password(self, password):
        """Genera el hash de la contraseña"""
        salt = gensalt()
        self.password_hash = hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        """Verifica la contraseña"""
        return checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'