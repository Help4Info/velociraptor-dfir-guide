# Installation Guide

## Prerequisites

- Ubuntu 24.04 (Server)
- Windows 10/11 (Client)
- Network connectivity between server and client

## Server Installation (Ubuntu)

### 1. Download Velociraptor

```bash
# Download latest release
wget https://github.com/Velocidex/velociraptor/releases/download/v0.7.1/velociraptor-v0.7.1-linux-amd64

# Make executable
chmod +x velociraptor-v0.7.1-linux-amd64

# Move to PATH
sudo mv velociraptor-v0.7.1-linux-amd64 /usr/local/bin/velociraptor
```

### 2. Generate Configuration

```bash
velociraptor config generate -i
```

Follow the prompts:
- Frontend bind address: `0.0.0.0`
- Frontend bind port: `8000`
- GUI bind address: `0.0.0.0`
- GUI bind port: `8889`

This creates:
- `server.config.yaml` - Server configuration
- `client.config.yaml` - Client configuration

### 3. Create Admin User

```bash
velociraptor --config server.config.yaml user add admin --role administrator
```

### 4. Start Server

```bash
# Foreground (for testing)
velociraptor --config server.config.yaml frontend -v

# Background (production)
nohup velociraptor --config server.config.yaml frontend -v &
```

### 5. Install as Service (Optional)

```bash
velociraptor --config server.config.yaml service install
systemctl start velociraptor
systemctl enable velociraptor
```

## Client Installation (Windows)

### 1. Copy Files

Transfer to Windows:
- `velociraptor.exe` (Windows binary)
- `client.config.yaml`

### 2. Verify Configuration

Check `client.config.yaml`:
```yaml
Client:
  server_urls:
    - https://YOUR_SERVER_IP:8000/
```

### 3. Install as Service

```powershell
# Run as Administrator
velociraptor.exe --config client.config.yaml service install
```

### 4. Start Service

```powershell
net start Velociraptor
```

### 5. Verify Connection

Check server logs or GUI for client connection.

## Accessing the Console

1. Open browser: `https://SERVER_IP:8889`
2. Accept self-signed certificate
3. Login with admin credentials

## Troubleshooting

### Client not connecting

1. Check firewall (port 8000)
2. Verify `server_urls` in client config
3. Check server logs

### Certificate errors

1. Ensure client has correct CA certificate
2. Regenerate configs if needed

### Service won't start

```powershell
# Check service status
sc query Velociraptor

# View event logs
Get-EventLog -LogName Application -Source Velociraptor -Newest 10
```
