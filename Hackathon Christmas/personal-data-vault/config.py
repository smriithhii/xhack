import os

class Config:
    SECRET_KEY = "6ef65243ea6f1b2999b99c7afcc6eb55f8c4584e0f76d3184d5a93810dd42444"
    SQLALCHEMY_DATABASE_URI = 'sqlite:///vault.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = "6abad1d0bbdcb9c0619baf480d713c45f3e0bc0b9b32a1cd9308b3e01553d47d"
    # Add these CORS settings
    CORS_HEADERS = 'Content-Type'
    WTF_CSRF_ENABLED = False  # Disable CSRF for API endpoints