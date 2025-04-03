---
title: Release Notes - FastAPI Guard
description: Release notes for FastAPI Guard, detailing new features, improvements, and bug fixes
keywords: release notes, fastapi guard, security middleware, api security
---

# Release Notes

## v1.2.0 (2025-04-03)
### New Features
- Added dedicated `RateLimitManager` for improved rate limiting functionality
- TTLCache-based in-memory rate limiting still available
- Extended Redis support for distributed rate limiting

### Improvements
- Fixed rate limiting logic to properly handle rate limiting
- Standardized Singleton pattern across all handlers

## v1.1.0 (2025-03-21)
### New Features
- Added proper typing throughout the codebase
- Added custom Docker container for example app
- Added better Docker Compose support

### Improvements
- Fixed multiple typing issues across test files
- Improved documentation for Docker container usage
- Enhanced serialization of Redis data

## v1.0.0 (2025-02-19)
### New Features
- Added Redis integration for distributed state management

### Improvements
- Improved tests & testing coverage (100% coverage)

## v0.4.0 (2025-02-16)
### New Features
- Added `db_path` parameter to `IPInfoManager` for custom database locations

### Improvements
- Improved IPInfo database handling with local caching

### Bug Fixes
- Fixed Azure IP ranges download by adding proper User-Agent headers ([#19](https://github.com/rennf93/fastapi-guard/pull/19))
- Fixed cloud provider validation logic to properly filter invalid entries
- Resolved test coverage gaps on all test files

## v0.3.4 (2025-01-26)

### Bug Fixes
- Fixed issue with accepted `Headers` on `Swagger UI` access/requests.

## v0.3.3 (2024-12-14)

### Bug Fixes
- Fixed package structure to properly include all required modules
- Resolved import issues with handlers package
- Improved package installation reliability