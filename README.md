# Network Discovery Tool

## Quick Start for Customers

1. **Download both files**:
   - `NetworkDiscovery.ps1` (the script)
   - `NetworkDiscovery_Instructions.md` (detailed instructions)

2. **Run as Administrator**:
   - Right-click PowerShell → "Run as Administrator"
   - Navigate to folder with script
   - Run: `.\NetworkDiscovery.ps1`

3. **Send us the results**:
   - Script creates a timestamped file in the same folder
   - Email the generated `.txt` file to your IT consultant

## Advanced Options

### Standard Scan (Default)
```powershell
.\NetworkDiscovery.ps1
```
- Tests legitimate business websites and LOB applications
- Includes comprehensive traceroute analysis
- Safe for all corporate environments

### Quick Scan (Faster)
```powershell
.\NetworkDiscovery.ps1 -SkipTraceroute
```
- Skips detailed routing analysis for faster execution
- Good for basic connectivity assessment

### Full Site Scan (Comprehensive)
```powershell
.\NetworkDiscovery.ps1 -FullSiteScan
```
- Tests additional website categories (gaming, entertainment, etc.)
- Helps identify content filtering policies
- **Use with caution** - tests sites that may be inappropriate for some corporate environments

### Custom Output Location
```powershell
.\NetworkDiscovery.ps1 -OutputPath "C:\Temp\MyReport.txt"
```

## What This Tool Analyzes

### ✅ Network Configuration
- Active network adapters and IP addresses
- Network routing and gateways
- DNS server configuration

### ✅ Connectivity Testing
- **LOB applications**: Customized list for your organization (70+ applications available)
  - Current: Egnyte, Office365, NitroPDF, RingCentral
  - Available: Salesforce, Slack, QuickBooks, DocuSign, and many more
- **Popular legitimate websites** across 12+ categories
- **Optional**: Restricted content categories (with -FullSiteScan)

### ✅ Infrastructure Analysis
- Domain join status (AD, Azure AD/Entra ID)
- Proxy configuration
- Windows Firewall settings
- Installed security software

### ✅ Network Routing (Optional)
- Comprehensive traceroute analysis to key destinations
- Route pattern analysis for ZTNA/proxy detection
- DNS server routing paths

### ✅ Security Assessment
- Active network connections
- Banyan/SonicWall CSE infrastructure detection
- Filtering policy assessment

## For IT Consultants

### 🔧 Customizing for Different Clients
The script includes a comprehensive list of 70+ business applications that can be easily enabled:

1. **Edit the script file** before deploying to client
2. **Uncomment applications** the client uses by removing `# ` from the lines
3. **Add custom applications** using the same format
4. **Categories available**:
   - CRM & Sales (Salesforce, HubSpot, Pipedrive)
   - Collaboration (Slack, Teams, Zoom)
   - Project Management (Asana, Trello, Jira)
   - Cloud Storage (Dropbox, Box, Google Drive)
   - Accounting (QuickBooks, Xero, Sage)
   - And many more...

### 📝 Example Customization
```powershell
# Uncomment for a client using Salesforce and Slack:
"Salesforce" = @("*.salesforce.com", "login.salesforce.com", "*.force.com")
"Slack" = @("*.slack.com", "app.slack.com", "files.slack.com")
```

## Need Help?
- Read the full `NetworkDiscovery_Instructions.md` file
- Contact your IT consultant if you encounter issues

## Privacy & Security
- ✅ No personal data collected
- ✅ No passwords or credentials accessed
- ✅ Only technical network information gathered
- ✅ No changes made to system configuration
- ✅ Human-readable output format
