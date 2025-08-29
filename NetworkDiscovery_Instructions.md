# Network Discovery Script - Customer Instructions

## Overview
This PowerShell script will gather information about your computer's network configuration and connectivity to help us understand your current SonicWall CSE Banyan setup and plan your migration to FortiSASE.

**Important**: This script only **reads** information from your system. It does not make any changes to your configuration.

## Prerequisites

### Required Permissions
- You must run this script **as Administrator**
- The script requires elevated privileges to access network and system information

### System Requirements
- Windows PowerShell 5.1 or later (included in Windows 10/11)
- Windows 10, Windows 11, or Windows Server 2016+

## Step-by-Step Instructions

### Step 1: Download the Script
1. Save the `NetworkDiscovery.ps1` file to your computer
2. Recommended location: `C:\Temp\` or the same folder as these instructions

### Step 2: Open PowerShell as Administrator
1. Press `Windows Key + X`
2. Select **"Windows PowerShell (Admin)"** or **"Terminal (Admin)"**
3. If prompted by User Account Control (UAC), click **"Yes"**

### Step 3: Navigate to Script Location
```powershell
# If you saved it to C:\Temp\
cd C:\Temp\

# If you saved it to the same folder as these instructions
cd "C:\Path\To\Your\Script\Folder"
```

### Step 4: Set Execution Policy (If Needed)
If you get an execution policy error, run this command first:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
When prompted, type `Y` and press Enter.

### Step 5: Choose Your Scan Type

#### Standard Scan (Recommended)
```powershell
.\NetworkDiscovery.ps1
```
- Tests legitimate business websites and LOB applications
- Includes comprehensive traceroute analysis
- Takes 5-10 minutes to complete
- Safe for all corporate environments

#### Quick Scan (Faster)
```powershell
.\NetworkDiscovery.ps1 -SkipTraceroute
```
- Skips detailed routing analysis for faster execution
- Takes 2-3 minutes to complete
- Good for basic connectivity assessment

#### Comprehensive Policy Assessment
```powershell
.\NetworkDiscovery.ps1 -FullSiteScan
```
- Tests additional website categories to identify filtering policies
- Includes gaming, entertainment, and other categories typically blocked
- **Use only if requested** by your IT consultant
- Takes 10-15 minutes to complete

#### Custom Output Location
```powershell
.\NetworkDiscovery.ps1 -OutputPath "C:\Temp\MyNetworkReport.txt"
```

### Step 6: Wait for Completion
- The script will display progress information as it runs
- **Standard scan**: 5-10 minutes
- **Quick scan**: 2-3 minutes  
- **Full scan**: 10-15 minutes
- Do not close the PowerShell window while it's running

### Step 7: Locate the Results
- The script creates a timestamped report file in the same folder as the script
- File name format: `NetworkDiscovery_YYYYMMDD_HHMMSS.txt`
- The script will automatically open the file in Notepad when complete

## What the Script Analyzes

### 🔧 Network Configuration
- Active network adapters and IP addresses
- Network routing tables and gateways
- DNS server configuration
- Proxy settings

### 🌐 Connectivity Testing
- **LOB Applications**: Customized for your organization
  - Current active: Egnyte, Office365, NitroPDF, RingCentral
  - Script includes 70+ business applications that can be enabled as needed
  - Categories: CRM, Collaboration, Project Management, Cloud Storage, Accounting, HR, and more
- **Cloud Services**: AWS, Azure, Google Cloud
- **Popular Websites**: 60+ legitimate sites across 12 categories
- **Optional**: Additional categories (gaming, entertainment, etc.) with `-FullSiteScan`
- **Popular Websites**: 60+ legitimate sites across 12 categories
- **Optional**: Additional categories (gaming, entertainment, etc.) with `-FullSiteScan`

### 🔒 Security Infrastructure
- Domain join status (Active Directory, Azure AD/Entra ID)
- Installed security software (Banyan, SonicWall, antivirus, etc.)
- Windows Firewall configuration
- Active network connections and processes

### 🗺️ Network Routing Analysis
- Comprehensive traceroute to key destinations
- Route pattern analysis for ZTNA/proxy detection
- DNS server routing paths
- Infrastructure identification (CDNs, cloud providers, security appliances)

### 📊 Filtering Policy Assessment
- Internet access restrictions
- Content filtering effectiveness
- Unexpected access patterns
- Security policy gaps

## Report Features

### Human-Readable Format
- Clean, organized sections with clear headings
- Visual indicators (✓ for success, ✗ for failures)
- Summary analysis and recommendations
- No confusing timestamps on every line

### Intelligent Analysis
- Automatic detection of ZTNA infrastructure
- Identification of proxy/filtering appliances
- Assessment of security policy effectiveness
- Recommendations for network optimization

## Troubleshooting

### Common Issues and Solutions

#### "Execution Policy" Error
**Error**: `cannot be loaded because running scripts is disabled on this system`

**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### "Access Denied" Error
**Problem**: Script not running as Administrator

**Solution**: 
1. Close PowerShell
2. Right-click on PowerShell icon
3. Select "Run as Administrator"
4. Try again

#### Script Takes a Long Time
**Normal behavior**: 
- **Standard scan with traceroute**: 5-10 minutes
- **Full site scan**: 10-15 minutes
- Network tests and traceroute analysis take time

**What to do**: 
- Wait for completion (look for progress messages)
- Use `-SkipTraceroute` for faster execution if needed
- Do not close the window

#### No Output File Created
**Check**:
1. Look in the same folder as the script for the timestamped file
2. Check if PowerShell showed any error messages
3. Ensure you have write permissions to the folder
4. Try specifying a custom output path: `-OutputPath "C:\Temp\Report.txt"`

#### Traceroute Analysis Fails
**Common causes**:
- Network firewalls blocking traceroute
- ICMP disabled on network
- Very restrictive network policies

**Solution**: Use `-SkipTraceroute` to bypass this analysis

## Security and Privacy

### What We Access
- ✅ Network configuration (public information)
- ✅ Installed software list (names and versions only)
- ✅ System settings (non-sensitive)
- ✅ DNS and connectivity information
- ✅ Network routing paths
- ✅ Windows services status

### What We DON'T Access
- ❌ Personal files or documents
- ❌ Passwords or credentials
- ❌ Email content
- ❌ Browsing history
- ❌ Application data
- ❌ User personal information
- ❌ File contents

### Data Collection Details
- **Website testing**: Only tests if sites are reachable (no content accessed)
- **DNS queries**: Only domain name resolution (no browsing data)
- **Network paths**: Only routing information (no data transmitted)
- **Software detection**: Only installed program names (no configuration details)

### Data Sharing
- The output file contains technical network information only
- No personally identifiable information is collected
- You can review the entire output file before sharing
- Send only the generated `.txt` file to your IT consultant

## After Running the Script

### Review the Output
1. Open the generated report file (opens automatically in Notepad)
2. Review the contents - it's all technical network information
3. Look for any sensitive information you're uncomfortable sharing (there shouldn't be any)
4. Note the clear, human-readable format with sections and summaries

### Understanding the Report
The report includes several main sections:
- **Network Adapters**: Your network connections and IP addresses
- **DNS Configuration**: Your DNS servers
- **Domain Status**: Whether you're joined to Active Directory or Azure AD
- **LOB Application Connectivity**: Tests to your business applications
- **Website Connectivity**: Internet access testing
- **Traceroute Analysis**: Network routing paths (if not skipped)
- **Security Software**: Installed security applications and services

### Share with Your IT Team
1. Email the `.txt` file to your designated IT consultant
2. The file name includes the date/time it was generated
3. Keep a copy for your records if desired
4. Mention which scan type you used (standard, quick, or full)

### Cleanup (Optional)
1. You can delete the script file after use: `NetworkDiscovery.ps1`
2. The output file can be deleted after sharing with IT
3. Reset execution policy if desired:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser
   ```

## Support

If you encounter any issues:

1. **Take a screenshot** of any error messages
2. **Note the exact step** where the problem occurred
3. **Note which scan type** you were trying to run
4. **Contact your IT consultant** with:
   - Screenshot of the error
   - Description of what you were doing
   - Your Windows version (Windows 10/11)
   - Which command you used to run the script

## Sample Output Preview

The new human-readable report format looks like:

```
============================================================
NETWORK DISCOVERY REPORT
============================================================
Generated: August 29, 2025 at 02:30 PM
Computer: DESKTOP-ABC123
Scan Type: STANDARD SCAN (legitimate sites only)

[SUMMARY] Report saved to: .\NetworkDiscovery_20250829_143015.txt

============================================================
NETWORK ADAPTERS
============================================================

--- Active Network Connections: ---
* Wi-Fi
  Type: Intel(R) Wi-Fi 6E AX211 160MHz
  Speed: 721 Mbps
  IP Address: 192.168.1.100/24

============================================================
LOB APPLICATION CONNECTIVITY
============================================================

--- Egnyte Application: ---
  [SUCCESS] egnyte.com resolves to: 34.102.136.180, 34.149.100.209
  [SUCCESS] egnyte.com - Connected successfully

--- Office365 Application: ---
  [SUCCESS] outlook.office365.com resolves to: 52.97.148.132
  [SUCCESS] outlook.office365.com - Connected successfully

--- Salesforce Application: ---
  [SUCCESS] salesforce.com resolves to: 136.146.176.122
  [SUCCESS] salesforce.com - Connected successfully

--- Slack Application: ---
  [SUCCESS] slack.com resolves to: 52.85.151.101
  [SUCCESS] slack.com - Connected successfully
```

## Advanced Usage

### For IT Professionals
If you're comfortable with PowerShell, you can customize the scan:

```powershell
# Quick assessment without routing analysis
.\NetworkDiscovery.ps1 -SkipTraceroute

# Comprehensive policy assessment
.\NetworkDiscovery.ps1 -FullSiteScan

# Custom output location with full analysis
.\NetworkDiscovery.ps1 -OutputPath "\\server\share\reports\network_report.txt"

# Fast comprehensive scan
.\NetworkDiscovery.ps1 -FullSiteScan -SkipTraceroute
```

### Customizing LOB Applications for Different Clients

The script includes a comprehensive list of 70+ popular business applications that can be easily enabled or disabled by commenting/uncommenting lines in the script.

#### 🔧 How to Customize:

1. **Open the script file** in a text editor
2. **Find the LOB Applications section** (around line 40)
3. **Uncomment applications** the client uses by removing `# ` from the beginning of lines
4. **Add custom applications** following the same format

#### 📋 Available Application Categories:

**CRM & Sales:**
- Salesforce, HubSpot, Pipedrive, Zoho CRM

**Collaboration & Communication:**
- Slack, Microsoft Teams, Zoom, WebEx, GoToMeeting, Discord

**Project Management:**
- Asana, Trello, Monday.com, Jira, Confluence, Notion, ClickUp

**Cloud Storage & File Sharing:**
- Dropbox, Box, Google Drive, OneDrive, SharePoint

**Accounting & Finance:**
- QuickBooks, Xero, Sage, FreshBooks, Wave

**HR & Payroll:**
- ADP, Paychex, BambooHR, Workday, Gusto

**ERP Systems:**
- NetSuite, SAP, Oracle, Dynamics365

**Design & Creative:**
- Adobe Creative Suite, Canva, Figma, InVision

**Development & IT:**
- GitHub, GitLab, Jenkins, Docker, AWS, Azure, Google Cloud

**Marketing & Analytics:**
- Google Analytics, Mailchimp, Constant Contact, HootSuite

**E-commerce:**
- Shopify, BigCommerce, WooCommerce, Magento

**Legal & Compliance:**
- DocuSign, HelloSign, PandaDoc, LegalZoom

**Industry-Specific:**
- Procore (Construction), AutoCAD (Engineering), Epic/Cerner (Healthcare)

**Backup & Security:**
- Carbonite, Backblaze, LastPass, 1Password, Bitwarden

**Education & Training:**
- Blackboard, Canvas, Moodle, Coursera, Udemy

#### 💡 Example Customization:

```powershell
# For a client using Salesforce and Slack, uncomment these lines:
"Salesforce" = @("*.salesforce.com", "login.salesforce.com", "*.force.com")
"Slack" = @("*.slack.com", "app.slack.com", "files.slack.com")

# For a client using QuickBooks and DocuSign:
"QuickBooks" = @("*.intuit.com", "qbo.intuit.com", "*.quickbooks.com")
"DocuSign" = @("*.docusign.com", "*.docusign.net")

# To add a custom application not in the list:
"CustomApp" = @("app.customdomain.com", "*.customdomain.com", "api.customdomain.com")
```

#### 🚀 Benefits of This Approach:
- **One script fits all clients** - No need for separate versions
- **Easy customization** - Just uncomment relevant applications
- **Comprehensive coverage** - 70+ popular business apps included
- **Organized by category** - Easy to find relevant applications
- **Future-proof** - Easy to add new applications as they become popular

### Understanding Scan Types
- **Standard**: Tests ~60 legitimate websites + active LOB apps + traceroute (recommended)
- **Quick**: Same as standard but skips traceroute (2-3 minutes)
- **Full**: Adds 50+ additional sites in restricted categories (policy assessment)

---

## Quick Reference for IT Professionals

### 🚀 Pre-Deployment Checklist:
1. **Edit script** to uncomment client's LOB applications
2. **Test locally** if possible
3. **Choose scan type** based on client environment and time constraints
4. **Provide instructions** to client contact

### 📝 Common LOB App Combinations:

**Small Business:**
```powershell
"Office365" = @("*.office365.com", "*.microsoftonline.com")
"QuickBooks" = @("*.intuit.com", "qbo.intuit.com")
"Dropbox" = @("*.dropbox.com", "dropbox.com")
```

**Sales Organization:**
```powershell
"Salesforce" = @("*.salesforce.com", "login.salesforce.com")
"Slack" = @("*.slack.com", "app.slack.com")
"Zoom" = @("*.zoom.us", "zoom.us")
```

**Creative Agency:**
```powershell
"Adobe_Creative" = @("*.adobe.com", "*.adobe.io")
"Figma" = @("*.figma.com", "figma.com")
"Slack" = @("*.slack.com", "app.slack.com")
```

**Healthcare:**
```powershell
"Epic" = @("*.epic.com", "*.epiccare.com")
"DocuSign" = @("*.docusign.com", "*.docusign.net")
"Office365" = @("*.office365.com", "*.microsoftonline.com")
```

### ⏱️ Estimated Execution Times:
- **Quick scan** (`-SkipTraceroute`): 2-3 minutes
- **Standard scan**: 5-10 minutes  
- **Full scan** (`-FullSiteScan`): 10-15 minutes
- **Full + Quick** (`-FullSiteScan -SkipTraceroute`): 5-8 minutes

### 📋 Report Analysis Tips:
- Look for **[ERROR]** entries in LOB app connectivity
- Check **routing patterns** for proxy/ZTNA infrastructure
- Review **DNS resolution** for filtering or redirection
- Examine **firewall rules** for security software presence
- Analyze **filtering policies** if using `-FullSiteScan`

**Questions?** Contact your IT consultant for assistance.
