---
title: Release Notes - FastAPI Guard
description: Release notes for FastAPI Guard, detailing new features, improvements, and bug fixes
keywords: release notes, fastapi guard, security middleware, api security
---

# Release Notes

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