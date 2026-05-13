from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from bcrypt import gensalt, hashpw, checkpw

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='vendedor')  # admin, vendedor, bodega

    # Relación con libros
    libros_creados = db.relationship('Libro', backref='creado_por', lazy=True, foreign_keys='Libro.creado_por_id')
    libros_editados = db.relationship('Libro', backref='editado_por', lazy=True, foreign_keys='Libro.editado_por_id')

    def set_password(self, password):
        salt = gensalt()
        self.password_hash = hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        return checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


class Libro(db.Model):
    __tablename__ = 'libros'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    precio = db.Column(db.Float, nullable=False)
    autor = db.Column(db.String(150), nullable=False)
    existencias = db.Column(db.Integer, nullable=False, default=0)

    # Auditoría (opcional pero recomendado)
    fecha_creacion = db.Column(db.DateTime, default=db.func.current_timestamp())
    fecha_actualizacion = db.Column(db.DateTime, default=db.func.current_timestamp(),
                                    onupdate=db.func.current_timestamp())
    creado_por_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    editado_por_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<Libro {self.nombre} - Stock: {self.existencias}>'

    def set_password(self, password):
        """Genera el hash de la contraseña"""
        salt = gensalt()
        self.password_hash = hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        """Verifica la contraseña"""
        return checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'