# Hackathon
# Personal Data Vault

## Overview
The Personal Data Vault API is a secure backend service for managing sensitive user data, including passwords, files, and personal information. Built with Flask, it employs robust encryption, secure authentication, and data integrity measures to ensure user data remains safe.

## Features
- **User Authentication**: Secure user registration and login with JWT-based token management.
- **File Upload & Encryption**: Users can upload sensitive files, which are encrypted before storage.
- **Password Management**: Encrypted password storage and retrieval for various services.
- **Breach Detection**: Integration with the "Have I Been Pwned" API for password and account breach detection.
- **File Sharing**: Share sensitive files securely with other users.
- **Rate Limiting**: API endpoints are rate-limited to protect against abuse.
- **Audit Logging**: Logs actions for accountability and debugging purposes.
- **Secure Sessions**: Tracks user sessions with token expiration and device info.

## Tech Stack
- **Backend Framework**: Flask
- **Database**: SQLite (can be configured for other relational databases)
- **Encryption**: AES for file and password encryption
- **APIs Used**: "Have I Been Pwned" for breach detection
- **Rate Limiting**: Flask-Limiter
- **Frontend**: Placeholder setup for integration with future frontend applications

## Project Structure

## Key Modules
- **`auth.py`**: Handles user authentication and password verification.
- **`breach_detection.py`**: Checks passwords and accounts against known breaches.
- **`encryption_utils.py`**: Provides AES-based encryption and decryption utilities.
- **`models.py`**: Defines database models for users, files, sessions, and logs.
- **`routes.py`**: Implements API endpoints for user actions.

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-username/personal-data-vault.git
   cd personal-data-vault

