#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Network and System Discovery Script for LOB Application Analysis
.DESCRIPTION
    This script gathers information about network configuration, routing, 
    DNS resolution, and connectivity to LOB applications to understand
    current SonicWall CSE Banyan setup and network architecture.
.PARAMETER OutputPath
    Path where the report file will be saved. Defaults to current directory.
.PARAMETER FullSiteScan
    Switch to enable testing of additional website categories typically blocked
    in corporate environments (gaming, adult content, gambling, etc.) to assess
    filtering policies. Use with caution in corporate environments.
.PARAMETER SkipTraceroute
    Switch to skip the comprehensive traceroute analysis, which can be time-consuming.
    Use this for faster scans when routing analysis is not needed.
.EXAMPLE
    .\NetworkDiscovery.ps1
    Runs standard network discovery with legitimate websites and full traceroute analysis
.EXAMPLE
    .\NetworkDiscovery.ps1 -FullSiteScan
    Runs comprehensive scan including potentially blocked categories
.EXAMPLE
    .\NetworkDiscovery.ps1 -SkipTraceroute
    Runs standard scan but skips traceroute analysis for faster execution
.EXAMPLE
    .\NetworkDiscovery.ps1 -FullSiteScan -SkipTraceroute
    Runs full site scan but skips traceroute for comprehensive but faster analysis
.NOTES
    Run as Administrator for best results
    Created for investigating SonicWall CSE Banyan configuration
    FullSiteScan may test sites inappropriate for some corporate environments
    Traceroute analysis can take 5-10 minutes but provides valuable routing insights
#>

param(
    [string]$OutputPath = ".\NetworkDiscovery_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",
    [switch]$FullSiteScan = $false,
    [switch]$SkipTraceroute = $false
)

# LOB Applications to test
# 
# INSTRUCTIONS FOR CUSTOMIZATION:
# 1. Keep the current active applications (Egnyte, Office365, NitroPDF, RingCentral) as-is
# 2. To add applications for a specific client, uncomment the relevant lines by removing the "# "
# 3. To disable an application, add "# " at the beginning of the line
# 4. You can add custom applications following the same format:
#    "AppName" = @("domain1.com", "*.domain2.com", "subdomain.domain3.com")
#
# Current active applications for this client:
$LOBApps = @{
    "Egnyte" = @("*.egnyte.com", "egnyte.com")
    "Office365" = @("*.office365.com", "*.microsoftonline.com", "outlook.office365.com", "login.microsoftonline.com")
    "NitroPDF" = @("*.nitropdf.com", "nitropdf.com")
    "RingCentral" = @("*.ringcentral.com", "ringcentral.com", "*.zoom.us")
    
    # Additional LOB Applications - Uncomment as needed for specific clients:
    
    # CRM & Sales
    # "Salesforce" = @("*.salesforce.com", "login.salesforce.com", "*.force.com")
    # "HubSpot" = @("*.hubspot.com", "app.hubspot.com")
    # "Pipedrive" = @("*.pipedrive.com", "app.pipedrive.com")
    # "Zoho_CRM" = @("*.zoho.com", "crm.zoho.com", "accounts.zoho.com")
    
    # Collaboration & Communication
    # "Slack" = @("*.slack.com", "app.slack.com", "files.slack.com")
    # "Microsoft_Teams" = @("teams.microsoft.com", "*.teams.microsoft.com")
    # "Zoom" = @("*.zoom.us", "zoom.us", "web.zoom.us")
    # "WebEx" = @("*.webex.com", "*.ciscospark.com")
    # "GoToMeeting" = @("*.gotomeeting.com", "*.logmeininc.com")
    # "Discord" = @("*.discord.com", "discord.com")
    
    # Project Management
    # "Asana" = @("*.asana.com", "app.asana.com")
    # "Trello" = @("*.trello.com", "trello.com")
    # "Monday" = @("*.monday.com", "auth.monday.com")
    # "Jira" = @("*.atlassian.net", "*.jira.com")
    # "Confluence" = @("*.atlassian.net", "*.confluence.com")
    # "Notion" = @("*.notion.so", "notion.so")
    # "ClickUp" = @("*.clickup.com", "app.clickup.com")
    
    # Cloud Storage & File Sharing
    # "Dropbox" = @("*.dropbox.com", "dropbox.com", "dl.dropboxusercontent.com")
    # "Box" = @("*.box.com", "app.box.com", "*.boxcdn.net")
    # "Google_Drive" = @("drive.google.com", "docs.google.com", "*.googleapis.com")
    # "OneDrive" = @("onedrive.live.com", "*.sharepoint.com", "graph.microsoft.com")
    # "SharePoint" = @("*.sharepoint.com", "*.sharepointonline.com")
    
    # Accounting & Finance
    # "QuickBooks" = @("*.intuit.com", "qbo.intuit.com", "*.quickbooks.com")
    # "Xero" = @("*.xero.com", "login.xero.com")
    # "Sage" = @("*.sage.com", "*.sageone.com")
    # "FreshBooks" = @("*.freshbooks.com", "my.freshbooks.com")
    # "Wave" = @("*.waveapps.com", "waveapps.com")
    
    # HR & Payroll
    # "ADP" = @("*.adp.com", "workforcenow.adp.com")
    # "Paychex" = @("*.paychex.com", "myapps.paychex.com")
    # "BambooHR" = @("*.bamboohr.com", "*.bamboohr.co.uk")
    # "Workday" = @("*.workday.com", "*.myworkday.com")
    # "Gusto" = @("*.gusto.com", "app.gusto.com")
    
    # ERP Systems
    # "NetSuite" = @("*.netsuite.com", "system.netsuite.com")
    # "SAP" = @("*.sap.com", "*.sapbydesign.com", "*.successfactors.com")
    # "Oracle" = @("*.oracle.com", "*.oraclecloud.com")
    # "Dynamics365" = @("*.dynamics.com", "*.crm.dynamics.com")
    
    # Design & Creative
    # "Adobe_Creative" = @("*.adobe.com", "*.adobe.io", "creativecloud.adobe.com")
    # "Canva" = @("*.canva.com", "canva.com")
    # "Figma" = @("*.figma.com", "figma.com")
    # "InVision" = @("*.invisionapp.com", "*.invision.io")
    
    # Development & IT
    # "GitHub" = @("github.com", "*.github.com", "api.github.com")
    # "GitLab" = @("gitlab.com", "*.gitlab.com")
    # "Bitbucket" = @("bitbucket.org", "*.atlassian.net")
    # "Jenkins" = @("*.jenkins.io", "jenkins.io")
    # "Docker" = @("*.docker.com", "docker.com", "hub.docker.com")
    # "AWS" = @("*.amazonaws.com", "console.aws.amazon.com")
    # "Azure" = @("portal.azure.com", "*.azure.com", "*.azurewebsites.net")
    # "Google_Cloud" = @("console.cloud.google.com", "*.googleapis.com")
    
    # Marketing & Analytics
    # "Google_Analytics" = @("analytics.google.com", "*.google-analytics.com")
    # "Mailchimp" = @("*.mailchimp.com", "login.mailchimp.com")
    # "Constant_Contact" = @("*.constantcontact.com", "login.constantcontact.com")
    # "HootSuite" = @("*.hootsuite.com", "hootsuite.com")
    # "Buffer" = @("*.buffer.com", "buffer.com")
    
    # E-commerce
    # "Shopify" = @("*.shopify.com", "*.myshopify.com", "shopify.com")
    # "BigCommerce" = @("*.bigcommerce.com", "login.bigcommerce.com")
    # "WooCommerce" = @("woocommerce.com", "*.woocommerce.com")
    # "Magento" = @("*.magento.com", "magento.com")
    
    # Legal & Compliance
    # "DocuSign" = @("*.docusign.com", "*.docusign.net")
    # "HelloSign" = @("*.hellosign.com", "hellosign.com")
    # "PandaDoc" = @("*.pandadoc.com", "app.pandadoc.com")
    # "LegalZoom" = @("*.legalzoom.com", "legalzoom.com")
    
    # Industry-Specific
    # "Procore" = @("*.procore.com", "app.procore.com")              # Construction
    # "AutoCAD" = @("*.autodesk.com", "web.autocad.com")             # Engineering/CAD
    # "Epic" = @("*.epic.com", "*.epiccare.com")                     # Healthcare
    # "Cerner" = @("*.cerner.com", "*.cernerworks.com")              # Healthcare
    # "Blackbaud" = @("*.blackbaud.com", "*.blackbaudhosting.com")   # Non-profit
    # "DonorPerfect" = @("*.donorperfect.com", "donorperfect.com")   # Non-profit
    # "MLS" = @("*.mls.com", "*.mlslistings.com")                    # Real Estate
    # "ChurchCRM" = @("*.churchcrm.com", "churchcrm.com")            # Religious
    
    # Backup & Security
    # "Carbonite" = @("*.carbonite.com", "carbonite.com")
    # "Backblaze" = @("*.backblaze.com", "backblaze.com")
    # "CrashPlan" = @("*.code42.com", "*.crashplan.com")
    # "LastPass" = @("*.lastpass.com", "lastpass.com")
    # "1Password" = @("*.1password.com", "1password.com")
    # "Bitwarden" = @("*.bitwarden.com", "bitwarden.com")
    
    # Education & Training
    # "Blackboard" = @("*.blackboard.com", "*.bblearn.com")
    # "Canvas" = @("*.instructure.com", "*.canvaslms.com")
    # "Moodle" = @("*.moodle.com", "moodlecloud.com")
    # "Coursera" = @("*.coursera.org", "coursera.org")
    # "Udemy" = @("*.udemy.com", "udemy.com")
}

# Common legitimate websites across various categories for connectivity testing
$CommonWebsites = @{
    "Search Engines" = @("google.com", "bing.com", "duckduckgo.com")
    "Social Media" = @("linkedin.com", "facebook.com", "twitter.com", "instagram.com", "youtube.com")
    "News & Media" = @("cnn.com", "bbc.com", "reuters.com", "npr.org", "apnews.com")
    "Cloud Services" = @("aws.amazon.com", "azure.microsoft.com", "cloud.google.com", "dropbox.com", "box.com")
    "Software & Tech" = @("github.com", "stackoverflow.com", "adobe.com", "salesforce.com", "atlassian.com")
    "E-commerce" = @("amazon.com", "ebay.com", "walmart.com", "target.com", "shopify.com")
    "Financial" = @("chase.com", "bankofamerica.com", "wellsfargo.com", "paypal.com", "americanexpress.com")
    "Education" = @("coursera.org", "edx.org", "udemy.com", "khanacademy.org", "mit.edu")
    "Government" = @("irs.gov", "usps.com", "dmv.org", "usa.gov", "cdc.gov")
    "Reference" = @("wikipedia.org", "dictionary.com", "weather.com", "maps.google.com")
    "Productivity" = @("slack.com", "trello.com", "asana.com", "notion.so", "monday.com")
    "Security" = @("virustotal.com", "malwarebytes.com", "kaspersky.com", "symantec.com")
}

# Additional categories typically blocked in corporate environments (only tested with -FullSiteScan)
$RestrictedWebsites = @{
    "Gaming" = @("steam.com", "twitch.tv", "minecraft.net", "roblox.com", "epicgames.com")
    "Entertainment" = @("netflix.com", "hulu.com", "disney.com", "spotify.com", "pandora.com")
    "Dating" = @("match.com", "eharmony.com", "bumble.com", "tinder.com", "pof.com")
    "Gambling" = @("draftkings.com", "fanduel.com", "bet365.com", "caesars.com", "mgmresorts.com")
    "Adult Content" = @("pornhub.com", "xvideos.com", "redtube.com", "xhamster.com", "youporn.com")
    "Torrents & P2P" = @("thepiratebay.org", "kickasstorrents.to", "1337x.to", "rarbg.to", "torrentz2.eu")
    "Proxy & VPN" = @("nordvpn.com", "expressvpn.com", "protonvpn.com", "surfshark.com", "hidemyass.com")
    "Anonymous Browsing" = @("tor.org", "duckduckgo.com", "startpage.com", "searx.org")
    "Weapons & Violence" = @("gunbroker.com", "cabelas.com", "sportsmansguide.com", "ammunitiondepot.com")
    "Drugs & Alcohol" = @("leafly.com", "weedmaps.com", "totalwine.com", "drizly.com")
}

# Common Banyan/SonicWall CSE domains and IPs
$BanyanDomains = @(
    "*.banyanops.com",
    "*.banyansecurity.io", 
    "*.sonicwall.com",
    "console.banyanops.com",
    "net.banyanops.com",
    "api.banyanops.com"
)

function Write-LogEntry {
    param([string]$Message, [string]$Type = "INFO")
    
    # Create clean, readable output without timestamps for most entries
    switch ($Type) {
        "HEADER" { 
            $logEntry = "`n" + "=" * 60
            $logEntry += "`n$Message"
            $logEntry += "`n" + "=" * 60
        }
        "SECTION" {
            $logEntry = "`n--- $Message ---"
        }
        "RESULT" {
            $logEntry = "  [SUCCESS] $Message"
        }
        "ERROR" {
            $logEntry = "  [ERROR] $Message"
        }
        "SUMMARY" {
            $logEntry = "`n[SUMMARY] $Message"
        }
        default {
            $logEntry = "$Message"
        }
    }
    
    Write-Host $logEntry
    
    # Ensure the output directory exists
    $outputDir = Split-Path -Parent $OutputPath
    if ($outputDir -and !(Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    Add-Content -Path $OutputPath -Value $logEntry
}

function Get-NetworkAdapters {
    Write-LogEntry "NETWORK ADAPTERS" "HEADER"
    
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Name -notlike "*Loopback*"}
    
    Write-LogEntry "Active Network Connections:" "SECTION"
    foreach ($adapter in $adapters) {
        # Skip virtual and less important adapters for cleaner output
        if ($adapter.Name -like "*Wi-Fi*" -or $adapter.Name -like "*Ethernet*" -or $adapter.Name -like "*Bridge*") {
            Write-LogEntry "* $($adapter.Name)"
            Write-LogEntry "  Type: $($adapter.InterfaceDescription)"
            Write-LogEntry "  Speed: $($adapter.LinkSpeed)"
            
            # Get IP configuration
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object {$_.AddressFamily -eq "IPv4"}
            foreach ($ip in $ipConfig) {
                Write-LogEntry "  IP Address: $($ip.IPAddress)/$($ip.PrefixLength)"
            }
            Write-LogEntry ""
        }
    }
}

function Get-RoutingTable {
    Write-LogEntry "NETWORK ROUTING" "HEADER"
    
    Write-LogEntry "Key Network Routes:" "SECTION"
    
    # Get default gateway
    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($defaultRoute) {
        Write-LogEntry "* Default Gateway: $($defaultRoute.NextHop) (via $($defaultRoute.InterfaceAlias))"
    }
    
    # Get local network routes (more readable)
    $localRoutes = Get-NetRoute | Where-Object {
        $_.DestinationPrefix -like "10.*" -or 
        $_.DestinationPrefix -like "192.168.*" -or 
        $_.DestinationPrefix -like "172.*"
    } | Sort-Object DestinationPrefix | Select-Object -First 5
    
    foreach ($route in $localRoutes) {
        Write-LogEntry "* Local Network: $($route.DestinationPrefix) via $($route.InterfaceAlias)"
    }
}

function Get-DNSConfiguration {
    Write-LogEntry "DNS CONFIGURATION" "HEADER"
    
    Write-LogEntry "DNS Servers:" "SECTION"
    
    $dnsServers = Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses -ne $null -and $_.InterfaceAlias -notlike "*Loopback*"}
    
    # Group by unique DNS servers to avoid repetition
    $uniqueDNS = @{}
    foreach ($dns in $dnsServers) {
        foreach ($server in $dns.ServerAddresses) {
            if (-not $uniqueDNS.ContainsKey($server)) {
                $uniqueDNS[$server] = $dns.InterfaceAlias
            }
        }
    }
    
    foreach ($server in $uniqueDNS.Keys) {
        Write-LogEntry "* $server (via $($uniqueDNS[$server]))"
    }
}

function Get-DomainJoinStatus {
    Write-LogEntry "=== DOMAIN JOIN STATUS ===" "HEADER"
    
    try {
        # Get computer system information
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $domainRole = $computerSystem.DomainRole
        
        # Domain role meanings:
        # 0 = Standalone Workstation, 1 = Member Workstation, 2 = Standalone Server
        # 3 = Member Server, 4 = Backup Domain Controller, 5 = Primary Domain Controller
        
        $roleNames = @{
            0 = "Standalone Workstation (Workgroup)"
            1 = "Domain-joined Workstation" 
            2 = "Standalone Server (Workgroup)"
            3 = "Domain-joined Server"
            4 = "Backup Domain Controller"
            5 = "Primary Domain Controller"
        }
        
        Write-LogEntry "Computer Name: $($computerSystem.Name)"
        Write-LogEntry "Domain Role: $($roleNames[$domainRole])"
        Write-LogEntry "Domain/Workgroup: $($computerSystem.Domain)"
        Write-LogEntry "Part of Domain: $($computerSystem.PartOfDomain)"
        
        # Check for Azure AD/Entra ID join status
        try {
            $dsregStatus = & dsregcmd /status 2>$null
            if ($dsregStatus) {
                Write-LogEntry ""
                Write-LogEntry "Azure AD/Entra ID Status:"
                
                # Parse dsregcmd output for key information
                foreach ($line in $dsregStatus) {
                    if ($line -match "AzureAdJoined\s*:\s*(.+)") {
                        Write-LogEntry "  Azure AD Joined: $($matches[1].Trim())"
                    }
                    elseif ($line -match "DomainJoined\s*:\s*(.+)") {
                        Write-LogEntry "  Domain Joined: $($matches[1].Trim())"
                    }
                    elseif ($line -match "WorkplaceJoined\s*:\s*(.+)") {
                        Write-LogEntry "  Workplace Joined: $($matches[1].Trim())"
                    }
                    elseif ($line -match "TenantName\s*:\s*(.+)") {
                        Write-LogEntry "  Tenant Name: $($matches[1].Trim())"
                    }
                    elseif ($line -match "TenantId\s*:\s*(.+)") {
                        Write-LogEntry "  Tenant ID: $($matches[1].Trim())"
                    }
                    elseif ($line -match "DeviceId\s*:\s*(.+)") {
                        Write-LogEntry "  Device ID: $($matches[1].Trim())"
                    }
                }
            }
        } catch {
            Write-LogEntry "Could not retrieve Azure AD status: $($_.Exception.Message)" "WARN"
        }
        
        # Check for hybrid join indicators
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
            $lastLoggedOnUser = Get-ItemProperty -Path $regPath -Name "LastLoggedOnUser" -ErrorAction SilentlyContinue
            if ($lastLoggedOnUser) {
                Write-LogEntry ""
                Write-LogEntry "Last Logged On User: $($lastLoggedOnUser.LastLoggedOnUser)"
            }
            
            # Check for certificate-based authentication (common with hybrid join)
            $certs = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
                $_.Subject -like "*CN=$($computerSystem.Name)*" -or 
                $_.EnhancedKeyUsageList -like "*Client Authentication*"
            }
            
            if ($certs) {
                Write-LogEntry ""
                Write-LogEntry "Found potential device certificates:"
                foreach ($cert in $certs) {
                    Write-LogEntry "  Subject: $($cert.Subject)"
                    Write-LogEntry "  Issuer: $($cert.Issuer)"
                    Write-LogEntry "  Valid Until: $($cert.NotAfter)"
                }
            }
            
        } catch {
            Write-LogEntry "Could not retrieve certificate information: $($_.Exception.Message)" "WARN"
        }
        
        # Check Group Policy application (indicates domain management)
        try {
            $gpResult = & gpresult /r /scope:computer 2>$null | Select-String "Applied Group Policy Objects"
            if ($gpResult) {
                Write-LogEntry ""
                Write-LogEntry "Group Policy is being applied (indicates domain management)"
            }
        } catch {
            # Silent fail - GP might not be available or accessible
        }
        
    } catch {
        Write-LogEntry "Error retrieving domain join status: $($_.Exception.Message)" "ERROR"
    }
    
    Write-LogEntry ""
}

function Test-DNSResolution {
    param([string]$Domain)
    
    try {
        $result = Resolve-DnsName -Name $Domain -ErrorAction Stop
        $ips = @()
        foreach ($record in $result) {
            if ($record.Type -eq "A") {
                $ips += $record.IPAddress
            }
        }
        if ($ips.Count -gt 0) {
            Write-LogEntry "$Domain resolves to: $($ips -join ', ')" "RESULT"
            return $true
        }
    } catch {
        Write-LogEntry "$Domain - [ERROR] DNS resolution failed" "ERROR"
        return $false
    }
}

function Test-Connectivity {
    param([string]$Target, [int]$Port = 443)
    
    try {
        $connection = Test-NetConnection -ComputerName $Target -Port $Port -WarningAction SilentlyContinue
        if ($connection.TcpTestSucceeded) {
            Write-LogEntry "$Target - [SUCCESS] Connected successfully" "RESULT"
            return $true
        } else {
            Write-LogEntry "$Target - [ERROR] Connection failed" "ERROR"
            return $false
        }
    } catch {
        Write-LogEntry "$Target - [ERROR] Test failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-ProxyConfiguration {
    Write-LogEntry "=== PROXY CONFIGURATION ===" "HEADER"
    
    # Check system proxy settings
    $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($proxySettings.ProxyEnable -eq 1) {
        Write-LogEntry "System Proxy Enabled: $($proxySettings.ProxyServer)"
        if ($proxySettings.ProxyOverride) {
            Write-LogEntry "Proxy Bypass: $($proxySettings.ProxyOverride)"
        }
    } else {
        Write-LogEntry "No system proxy configured"
    }
    
    # Check for PAC file
    if ($proxySettings.AutoConfigURL) {
        Write-LogEntry "PAC File URL: $($proxySettings.AutoConfigURL)"
    }
    
    Write-LogEntry ""
}

function Get-InstalledSoftware {
    Write-LogEntry "=== INSTALLED SOFTWARE (Security/Network Related) ===" "HEADER"
    
    $relevantSoftware = @("*banyan*", "*sonicwall*", "*forcepoint*", "*zscaler*", "*netskope*", "*cloudflare*", "*cisco*", "*palo*", "*fortinet*", "*watchguard*")
    
    foreach ($pattern in $relevantSoftware) {
        $software = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like $pattern}
        foreach ($app in $software) {
            Write-LogEntry "Found: $($app.Name) - Version: $($app.Version)"
        }
    }
    
    # Also check installed services
    $services = Get-Service | Where-Object {$_.DisplayName -like "*banyan*" -or $_.DisplayName -like "*sonicwall*" -or $_.DisplayName -like "*ztna*"}
    foreach ($service in $services) {
        Write-LogEntry "Service: $($service.DisplayName) - Status: $($service.Status)"
    }
    
    Write-LogEntry ""
}

function Test-LOBApplications {
    Write-LogEntry "LOB APPLICATION CONNECTIVITY" "HEADER"
    
    foreach ($app in $LOBApps.Keys) {
        Write-LogEntry "$app Application:" "SECTION"
        
        foreach ($domain in $LOBApps[$app]) {
            # Remove wildcard for testing
            $testDomain = $domain -replace '^\*\.', ''
            
            Test-DNSResolution -Domain $testDomain
            Test-Connectivity -Target $testDomain -Port 443
        }
    }
}

function Test-CommonWebsites {
    Write-LogEntry "COMMON WEBSITE CONNECTIVITY" "HEADER"
    
    if ($FullSiteScan) {
        Write-LogEntry "[WARNING] FULL SITE SCAN ENABLED - Testing ALL categories including potentially blocked content" "SUMMARY"
        Write-LogEntry "This scan includes gaming, entertainment, adult content, gambling, and other categories" "SUMMARY"
        Write-LogEntry "typically blocked in corporate environments to identify filtering policies." "SUMMARY"
    } else {
        Write-LogEntry "Testing connectivity to popular legitimate websites across various categories..." "SUMMARY"
        Write-LogEntry "Use -FullSiteScan switch to test additional restricted categories" "SUMMARY"
    }
    
    $totalSites = 0
    $successfulSites = 0
    $failedCategories = @()
    $allCategories = $CommonWebsites.Clone()
    
    # Add restricted categories if full scan is enabled
    if ($FullSiteScan) {
        foreach ($category in $RestrictedWebsites.Keys) {
            $allCategories[$category] = $RestrictedWebsites[$category]
        }
    }
    
    foreach ($category in $allCategories.Keys) {
        # Mark restricted categories clearly
        if ($RestrictedWebsites.ContainsKey($category)) {
            Write-LogEntry "${category} (Typically Blocked):" "SECTION"
        } else {
            Write-LogEntry "${category}:" "SECTION"
        }
        
        $categorySuccess = 0
        $categoryTotal = 0
        
        foreach ($domain in $allCategories[$category]) {
            $totalSites++
            $categoryTotal++
            
            if (Test-DNSResolution -Domain $domain) {
                if (Test-Connectivity -Target $domain -Port 443) {
                    $successfulSites++
                    $categorySuccess++
                }
            }
        }
        
        # Track categories with poor connectivity
        $categorySuccessRate = ($categorySuccess / $categoryTotal) * 100
        if ($categorySuccessRate -lt 50) {
            $failedCategories += "${category} (${categorySuccess}/${categoryTotal} successful)"
        }
        
        # Color code category summaries based on expected blocking
        if ($RestrictedWebsites.ContainsKey($category)) {
            if ($categorySuccess -eq 0) {
                Write-LogEntry "Category Summary: $categorySuccess/$categoryTotal sites accessible (EXPECTED - typically blocked)" "RESULT"
            } else {
                Write-LogEntry "Category Summary: $categorySuccess/$categoryTotal sites accessible (UNEXPECTED - should be blocked)" "ERROR"
            }
        } else {
            Write-LogEntry "Category Summary: $categorySuccess/$categoryTotal sites accessible" "SUMMARY"
        }
    }
    
    # Overall summary
    $overallSuccessRate = ($successfulSites / $totalSites) * 100
    Write-LogEntry "OVERALL INTERNET CONNECTIVITY SUMMARY" "SECTION"
    Write-LogEntry "Total sites tested: $totalSites"
    Write-LogEntry "Successful connections: $successfulSites"
    Write-LogEntry "Success rate: $([math]::Round($overallSuccessRate, 1))%"
    
    if ($failedCategories.Count -gt 0) {
        Write-LogEntry "Categories with connectivity issues:" "ERROR"
        foreach ($category in $failedCategories) {
            Write-LogEntry "  * $category" "ERROR"
        }
    }
    
    # Interpret results based on scan type
    if ($FullSiteScan) {
        Write-LogEntry "FULL SCAN ANALYSIS:" "SECTION"
        
        # Count legitimate vs restricted success rates
        $legitimateSuccess = 0
        $legitimateTotal = 0
        $restrictedSuccess = 0
        $restrictedTotal = 0
        
        foreach ($category in $CommonWebsites.Keys) {
            foreach ($domain in $CommonWebsites[$category]) {
                $legitimateTotal++
                # This is simplified - in practice you'd track individual results
            }
        }
        
        if ($RestrictedWebsites) {
            foreach ($category in $RestrictedWebsites.Keys) {
                foreach ($domain in $RestrictedWebsites[$category]) {
                    $restrictedTotal++
                }
            }
        }
        
        Write-LogEntry "Filtering Policy Assessment:"
        if ($overallSuccessRate -gt 90) {
            Write-LogEntry "[WARNING] Very permissive internet access - little to no content filtering detected" "ERROR"
        } elseif ($overallSuccessRate -gt 70) {
            Write-LogEntry "[SUCCESS] Moderate filtering - Some content categories appear to be blocked" "RESULT"
        } elseif ($overallSuccessRate -gt 50) {
            Write-LogEntry "[SUCCESS] Strong filtering - Significant content blocking detected" "RESULT"
        } else {
            Write-LogEntry "[SUCCESS] Very restrictive filtering - Most non-business sites appear blocked" "RESULT"
        }
    } else {
        # Standard scan interpretation
        if ($overallSuccessRate -gt 90) {
            Write-LogEntry "[SUCCESS] Excellent internet connectivity - No significant filtering detected" "RESULT"
        } elseif ($overallSuccessRate -gt 70) {
            Write-LogEntry "[WARNING] Good connectivity with some potential filtering" "ERROR"
        } elseif ($overallSuccessRate -gt 50) {
            Write-LogEntry "[WARNING] Moderate connectivity - Significant filtering may be present" "ERROR"
        } else {
            Write-LogEntry "[ERROR] Poor connectivity - Heavy filtering or network issues detected" "ERROR"
        }
    }
}

function Test-BanyanInfrastructure {
    Write-LogEntry "=== BANYAN/SONICWALL CSE INFRASTRUCTURE ===" "HEADER"
    
    foreach ($domain in $BanyanDomains) {
        $testDomain = $domain -replace '^\*\.', ''
        
        Write-LogEntry "Testing Banyan domain: $testDomain"
        if (Test-DNSResolution -Domain $testDomain) {
            Test-Connectivity -Target $testDomain -Port 443
        }
    }
    Write-LogEntry ""
}

function Get-NetworkTraces {
    Write-LogEntry "NETWORK TRACE ANALYSIS" "HEADER"
    Write-LogEntry "Performing traceroute analysis to identify network paths and potential filtering points..." "SUMMARY"
    
    # Key domains for traceroute analysis
    $traceDomains = @{
        "LOB Applications" = @("egnyte.com", "outlook.office365.com", "nitropdf.com", "ringcentral.com")
        "Cloud Infrastructure" = @("aws.amazon.com", "azure.microsoft.com", "cloud.google.com")
        "Popular Sites" = @("google.com", "facebook.com", "youtube.com", "linkedin.com")
        "CDN & Performance" = @("cloudflare.com", "akamai.com", "fastly.com")
        "Security Services" = @("virustotal.com", "malwarebytes.com")
    }
    
    # Add Banyan domains for ZTNA analysis
    $traceDomains["Banyan/ZTNA"] = @("console.banyanops.com", "net.banyanops.com", "sonicwall.com")
    
    foreach ($category in $traceDomains.Keys) {
        Write-LogEntry "$category Routing Analysis:" "SECTION"
        
        foreach ($domain in $traceDomains[$category]) {
            Write-LogEntry "Tracing route to $domain..." 
            
            try {
                $trace = Test-NetConnection -ComputerName $domain -TraceRoute -WarningAction SilentlyContinue
                
                if ($trace.TraceRoute) {
                    Write-LogEntry "Route to $domain ($($trace.RemoteAddress)):"
                    
                    for ($i = 0; $i -lt $trace.TraceRoute.Count; $i++) {
                        $hop = $trace.TraceRoute[$i]
                        $hopNum = $i + 1
                        
                        # Try to resolve hostname for better readability
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($hop).HostName
                            Write-LogEntry "  Hop $hopNum`: $hop ($hostname)"
                        } catch {
                            Write-LogEntry "  Hop $hopNum`: $hop"
                        }
                        
                        # Stop at 15 hops to keep output manageable
                        if ($i -ge 14) {
                            Write-LogEntry "  ... (truncated at 15 hops)"
                            break
                        }
                    }
                    
                    # Analyze the route for interesting patterns
                    $routeAnalysis = @()
                    foreach ($hop in $trace.TraceRoute) {
                        if ($hop -match "^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.") {
                            $routeAnalysis += "Private IP detected: $hop"
                        }
                        elseif ($hop -match "proxy|filter|firewall|gateway") {
                            $routeAnalysis += "Potential filtering device: $hop"
                        }
                        elseif ($hop -match "cloudflare|akamai|fastly|amazon|microsoft|google") {
                            $routeAnalysis += "CDN/Cloud provider: $hop"
                        }
                    }
                    
                    if ($routeAnalysis.Count -gt 0) {
                        Write-LogEntry "  Route Analysis:"
                        foreach ($analysis in $routeAnalysis) {
                            Write-LogEntry "    * $analysis" "RESULT"
                        }
                    }
                    
                } else {
                    Write-LogEntry "  No traceroute data available for $domain" "ERROR"
                }
                
            } catch {
                Write-LogEntry "  Traceroute to $domain failed: $($_.Exception.Message)" "ERROR"
            }
            
            Write-LogEntry ""
        }
    }
    
    # Additional traceroute analysis for DNS servers
    Write-LogEntry "DNS Server Routing Analysis:" "SECTION"
    $dnsServers = Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses -ne $null} | Select-Object -First 3
    
    foreach ($dns in $dnsServers) {
        foreach ($server in $dns.ServerAddresses | Select-Object -First 2) {
            if ($server -ne "::1" -and $server -ne "127.0.0.1") {
                Write-LogEntry "Tracing route to DNS server $server..."
                
                try {
                    $trace = Test-NetConnection -ComputerName $server -TraceRoute -WarningAction SilentlyContinue
                    
                    if ($trace.TraceRoute -and $trace.TraceRoute.Count -gt 1) {
                        Write-LogEntry "Route to DNS $server (via $($dns.InterfaceAlias)):"
                        for ($i = 0; $i -lt [Math]::Min(8, $trace.TraceRoute.Count); $i++) {
                            Write-LogEntry "  Hop $($i+1): $($trace.TraceRoute[$i])"
                        }
                    } else {
                        Write-LogEntry "  Direct connection or single hop to DNS server"
                    }
                } catch {
                    Write-LogEntry "  Could not trace to DNS server: $($_.Exception.Message)" "ERROR"
                }
                Write-LogEntry ""
            }
        }
    }
    
    Write-LogEntry "TRACEROUTE SUMMARY ANALYSIS:" "SECTION"
    Write-LogEntry "Review the traceroute results above for:"
    Write-LogEntry "* Multiple hops through private IP ranges (may indicate proxy/filtering)"
    Write-LogEntry "* Consistent routing patterns to different destinations"
    Write-LogEntry "* Unexpected geographic routing or CDN usage"
    Write-LogEntry "* Routing through security appliances or ZTNA infrastructure"
}

function Get-FirewallRules {
    Write-LogEntry "=== WINDOWS FIREWALL STATUS ===" "HEADER"
    
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        Write-LogEntry "Profile: $($profile.Name) - Enabled: $($profile.Enabled) - Default Inbound: $($profile.DefaultInboundAction) - Default Outbound: $($profile.DefaultOutboundAction)"
    }
    
    # Check for any rules that might indicate Banyan/ZTNA
    $suspiciousRules = Get-NetFirewallRule | Where-Object {
        $_.DisplayName -like "*banyan*" -or 
        $_.DisplayName -like "*sonicwall*" -or 
        $_.DisplayName -like "*ztna*" -or
        $_.DisplayName -like "*sase*"
    }
    
    if ($suspiciousRules) {
        Write-LogEntry "Found potentially relevant firewall rules:"
        foreach ($rule in $suspiciousRules) {
            Write-LogEntry "  Rule: $($rule.DisplayName) - Action: $($rule.Action) - Direction: $($rule.Direction)"
        }
    }
    Write-LogEntry ""
}

function Get-ProcessesAndConnections {
    Write-LogEntry "=== ACTIVE NETWORK CONNECTIONS ===" "HEADER"
    
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -and $_.RemotePort -eq 443}
    $uniqueRemotes = $connections | Sort-Object RemoteAddress -Unique | Select-Object -First 20
    
    foreach ($conn in $uniqueRemotes) {
        try {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            Write-LogEntry "Connection: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) | Process: $($process.Name)"
        } catch {
            Write-LogEntry "Connection: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) | Process: Unknown"
        }
    }
    Write-LogEntry ""
}

# Main execution
Write-LogEntry "NETWORK DISCOVERY REPORT" "HEADER"
Write-LogEntry "Generated: $(Get-Date -Format 'MMMM dd, yyyy at hh:mm tt')"
Write-LogEntry "Computer: $env:COMPUTERNAME"
if ($FullSiteScan) {
    Write-LogEntry "Scan Type: FULL SITE SCAN (includes restricted categories)" "SUMMARY"
} else {
    Write-LogEntry "Scan Type: STANDARD SCAN (legitimate sites only)" "SUMMARY"
}
Write-LogEntry "Report saved to: $OutputPath" "SUMMARY"

# Run all discovery functions
Get-NetworkAdapters
Get-RoutingTable
Get-DNSConfiguration
Get-DomainJoinStatus
Get-ProxyConfiguration
Get-InstalledSoftware
Get-FirewallRules
Test-BanyanInfrastructure
Test-LOBApplications
Test-CommonWebsites

if (-not $SkipTraceroute) {
    Get-NetworkTraces
} else {
    Write-LogEntry "TRACEROUTE ANALYSIS SKIPPED" "HEADER"
    Write-LogEntry "Traceroute analysis was skipped for faster execution." "SUMMARY"
    Write-LogEntry "Run without -SkipTraceroute to include routing analysis." "SUMMARY"
}

Get-ProcessesAndConnections

Write-LogEntry "Network discovery completed!" "HEADER"
Write-LogEntry "Results saved to: $OutputPath"

# Open the output file
if (Test-Path $OutputPath) {
    Write-Host "`nOpening results file..." -ForegroundColor Green
    Start-Process notepad.exe -ArgumentList $OutputPath
}
