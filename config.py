import os

class Config:
    SECRET_KEY = 'clave-secreta-jurislib'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:admin@localhost:5432/jurislib_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False