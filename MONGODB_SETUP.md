# MongoDB Setup for Swarm

This guide will help you set up MongoDB for the Swarm web security scanner.

## Option 1: MongoDB Atlas (Cloud - Recommended for Development)

### 1. Create Free MongoDB Atlas Account
1. Go to [mongodb.com/atlas](https://www.mongodb.com/atlas)
2. Sign up for a free account
3. Create a new cluster (choose the free M0 tier)
4. Wait for cluster to deploy (2-3 minutes)

### 2. Configure Database Access
1. Go to "Database Access" in Atlas dashboard
2. Click "Add New Database User"
3. Create username/password (save these!)
4. Give user "Read and write to any database" permissions

### 3. Configure Network Access
1. Go to "Network Access" in Atlas dashboard
2. Click "Add IP Address"
3. Choose "Allow Access from Anywhere" (0.0.0.0/0) for development
4. Confirm

### 4. Get Connection String
1. Go to "Clusters" and click "Connect"
2. Choose "Connect your application"
3. Copy the connection string
4. Replace `<username>` and `<password>` with your credentials
5. Replace `<dbname>` with `swarm_db`

Example connection string:
```
mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/swarm_db?retryWrites=true&w=majority
```

### 5. Configure Environment
Create a `.env` file in the `backend/` directory:
```bash
MONGODB_URL=mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/swarm_db?retryWrites=true&w=majority
DATABASE_NAME=swarm_db
```

## Option 2: Local MongoDB (For Production/Offline)

### macOS Installation
```bash
# Using Homebrew
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb/brew/mongodb-community
```

### Ubuntu/Debian Installation
```bash
# Import public key
wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | sudo apt-key add -

# Add MongoDB repository
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

# Install MongoDB
sudo apt update
sudo apt install -y mongodb-org

# Start MongoDB service
sudo systemctl start mongod
sudo systemctl enable mongod
```

### Windows Installation
1. Download MongoDB Community Server from [mongodb.com/download-center/community](https://www.mongodb.com/download-center/community)
2. Run the installer (choose "Complete" setup)
3. Install MongoDB as a Windows Service
4. MongoDB will start automatically

### Configure Local Environment
Create a `.env` file in the `backend/` directory:
```bash
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=swarm_db
```

## Verify Setup

### Test Database Connection
```bash
cd backend
python database.py
```

You should see:
```
🔌 Connecting to MongoDB at mongodb://...
✅ MongoDB connection successful
🗄️ Database 'swarm_db' initialized
✅ Created test scan: test_123
✅ Retrieved scan: https://example.com
✅ Test cleanup complete
🔌 Database connection closed
```

### Test API Health Check
```bash
# Start backend
cd backend
python main.py

# In another terminal, test health
curl http://localhost:8000/health
```

Expected response:
```json
{"status": "healthy", "database": "connected"}
```

## Database Collections

Swarm uses these MongoDB collections:

- **scan_runs**: Stores scan metadata and status
- **findings**: Security vulnerabilities discovered
- **scanned_pages**: Page-level scan results

## Troubleshooting

### Connection Issues
- **Atlas**: Check IP whitelist and credentials
- **Local**: Ensure MongoDB service is running: `brew services list | grep mongodb`

### Authentication Failed
- Double-check username/password in connection string
- Ensure user has proper database permissions

### Network Timeout
- For Atlas: Check network access settings
- For local: Ensure MongoDB is listening on correct port (27017)

### Dependencies
If you get import errors:
```bash
cd backend
pip install -r requirements.txt
```

## Security Notes

⚠️ **For production deployments:**

1. **Never use "Allow Access from Anywhere"** - whitelist specific IPs
2. **Use strong passwords** - generate random passwords for database users
3. **Enable authentication** - always use authenticated connections
4. **Use SSL/TLS** - Atlas uses this by default, enable for local setups
5. **Regular backups** - Atlas provides automatic backups

## Quick Commands

```bash
# Test MongoDB connection
cd backend && python database.py

# Start backend with MongoDB
cd backend && python main.py

# Check database health
curl http://localhost:8000/health

# View MongoDB logs (local)
tail -f /usr/local/var/log/mongodb/mongo.log  # macOS
sudo tail -f /var/log/mongodb/mongod.log      # Linux
```