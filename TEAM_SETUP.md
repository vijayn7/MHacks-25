# 🛡️ Swarm - Team Setup Guide

## Quick Start for Teammates

### 1. Clone and Install
```bash
git clone <your-repo-url>
cd MHacks-25
./setup.sh
```

### 2. Environment Setup
Create `backend/.env`:
```bash
MONGODB_URL=mongodb+srv://swarm_db:mhacks_25@swarm.wckys4q.mongodb.net/swarm_db?retryWrites=true&w=majority
DATABASE_NAME=swarm_db
```

### 3. Start Everything
```bash
# Option 1: All at once
./start.sh

# Option 2: Manual (3 terminals)
cd demo-app && npm start     # http://localhost:3001
cd backend && python main.py  # http://localhost:8000
cd frontend && npm start      # http://localhost:3000
```

## 📋 Team Task Distribution

### 🔍 Scanner Team
**Priority**: Add vulnerability scanners
**Files**: `scanner/`
**Tasks**:
- `cors_scanner.py` - CORS misconfiguration detection
- `xss_scanner.py` - XSS reflection with safe tokens
- `redirect_scanner.py` - Open redirect detection

**Template**: Use `scanner/header_scanner.py` as base

### 🎨 Frontend Team
**Priority**: Polish UI for demo appeal
**Files**: `frontend/src/`
**Tasks**:
- Live progress animations
- Risk severity dashboard
- Screenshot evidence viewer
- Copy-paste fix buttons

### 🛠️ Backend Team
**Priority**: Production features
**Files**: `backend/`
**Tasks**:
- PDF report generation
- Rate limiting
- Error handling
- CI/CD integration

## 🎯 Current Status

✅ **Working**: MongoDB + FastAPI + React + Playwright crawler
✅ **Integrated**: Real scanning pipeline
✅ **Demo Ready**: Vulnerable target app

## 🚨 Important Notes

- **Never commit `.env` files** (contains MongoDB credentials)
- **Test locally** before pushing
- **Screenshots/artifacts** auto-generated, don't commit
- **MongoDB Atlas** already configured and working

## 🧪 Testing

```bash
# Test full pipeline
curl http://localhost:8000/health
python quick_test.py

# Test vulnerability scanner
cd scanner && python header_scanner.py
```

## 🏆 Demo Requirements

**Demo App**: http://localhost:3001 (8 vulnerabilities)
**Scanner**: Real Playwright crawling + header analysis
**Database**: MongoDB Atlas with persistence
**Frontend**: Live SSE streaming + evidence display

**Judges will see**:
1. Live crawling progress
2. Real vulnerability discovery
3. Copy-paste fixes
4. Professional evidence (screenshots + headers)

## 📞 Quick Help

**MongoDB not connecting?**
- Check `backend/.env` file exists
- Verify connection string format

**Crawler failing?**
- Run `playwright install`
- Check demo app is running on :3001

**Frontend not starting?**
- Clear npm cache: `npm cache clean --force`
- Delete `node_modules` and reinstall

**Can't push to Git?**
- Check .gitignore excludes .env files
- Use `git status` to verify