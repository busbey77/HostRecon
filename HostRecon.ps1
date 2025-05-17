function Invoke-HostRecon{

    <#

    .SYNOPSIS

    A simplified version of the original HostRecon script that runs essential checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase. It gathers core information about the local system, users, and domain information while maintaining a lean profile.

    HostRecon Function: Invoke-HostRecon
    Author: Beau Bullock (@dafthack) with credit to Joff Thyer (@joff_thyer) for the portscan module.
    Simplified by: Cline
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
    .DESCRIPTION

    This function runs essential checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase. It gathers core information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection.

    .PARAMETER Portscan

    If this flag is added an outbound portscan will be initiated from the target system to allports.exposed. The top 50 ports as specified by the Nmap project will be scanned. This is useful in determining any egress filtering in use.
    
    .PARAMETER TopPorts

    This flag specifies the number of "top ports" to be scanned outbound from the system. Valid entries are 1-128. Default is 50.

    .PARAMETER DisableDomainChecks

    If this flag is added, domain-related checks will be skipped.

    .PARAMETER ExportCSV

    If this flag is added, results will be exported to a CSV file. Default location is c:\temp\hostrecon_results_[timestamp].csv.

    .Example

    C:\PS> Invoke-HostRecon

    Description
    -----------
    This command will run essential checks on the local system including system information, user details, security products, and domain information.

    .Example

    C:\PS> Invoke-HostRecon -Portscan -TopPorts 20

    Description
    -----------
    This command will run essential checks and perform an outbound portscan on the top 20 ports to allports.exposed.

    .Example

    C:\PS> Invoke-HostRecon -ExportCSV

    Description
    -----------
    This command will run essential checks and export the results to a CSV file.

    #>

    Param(
        [Parameter(Position = 0, Mandatory = $false)]
        [switch]
        $Portscan,

        [Parameter(Position = 1, Mandatory = $false)]
        [string]
        $TopPorts = "50",

        [Parameter(Position = 2, Mandatory = $false)]
        [switch]
        $DisableDomainChecks = $false,

        [ValidateRange(1,65535)][String[]]$Portlist = "",

        [Parameter(Position = 3, Mandatory = $false)]
        [switch]
        $ExportCSV = $false
    )

    # Create an array to store all results for CSV export
    $global:AllResults = @()
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $defaultCSVPath = "c:\temp\hostrecon_results_$timestamp.csv"

    Write-Output "[+] HostRecon - Simplified Reconnaissance Tool"
    Write-Output "[+] Starting scan at $(Get-Date)"
    Write-Output ""

    #Hostname
    Write-Output "[*] System Information"
    $Computer = $env:COMPUTERNAME
    Write-Output "Hostname: $Computer"
    $global:AllResults += [PSCustomObject]@{
        Category = "System Information"
        Item = "Hostname"
        Value = $Computer
    }

    #IP Information
    $ipinfoData = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True'
    Write-Output "IP Addresses:"
    foreach ($adapter in $ipinfoData) {
        foreach ($ip in $adapter.IPAddress) {
            Write-Output "- $ip ($($adapter.Description))"
            $global:AllResults += [PSCustomObject]@{
                Category = "Network"
                Item = "IP Address ($($adapter.Description))"
                Value = $ip
            }
        }
    }
    Write-Output ""

    #Current user and domain
    Write-Output "[*] User Information"
    $currentuser = $env:USERNAME
    $domain = $env:USERDOMAIN
    Write-Output "Domain: $domain"
    Write-Output "Current User: $currentuser"
    $global:AllResults += [PSCustomObject]@{
        Category = "User Information"
        Item = "Domain"
        Value = $domain
    }
    $global:AllResults += [PSCustomObject]@{
        Category = "User Information"
        Item = "Current User"
        Value = $currentuser
    }

    #Local Admins group
    Write-Output "Local Administrators:"
    $AdminsData = Get-WmiObject win32_groupuser | Where-Object { $_.GroupComponent -match 'administrators' -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")} | ForEach-Object {[wmi]$_.PartComponent } | Select-Object Caption,SID
    foreach ($admin in $AdminsData) {
        Write-Output "- $($admin.Caption)"
        $global:AllResults += [PSCustomObject]@{
            Category = "User Information"
            Item = "Local Admin"
            Value = $admin.Caption
        }
    }
    Write-Output ""

    #Active Network Connections (simplified)
    Write-Output "[*] Active Network Connections"
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $TCPProperties.GetActiveTcpConnections()
    
    $connectionCount = 0
    foreach($Connection in $Connections) {
        if ($Connection.State -eq "Established") {
            $connectionCount++
            $localIP = $Connection.LocalEndPoint.Address
            $localPort = $Connection.LocalEndPoint.Port
            $remoteIP = $Connection.RemoteEndPoint.Address
            $remotePort = $Connection.RemoteEndPoint.Port
            
            Write-Output "- $localIP`:$localPort -> $remoteIP`:$remotePort"
            
            $global:AllResults += [PSCustomObject]@{
                Category = "Network Connections"
                Item = "TCP Connection"
                Value = "$localIP`:$localPort -> $remoteIP`:$remotePort"
            }
        }
    }
    Write-Output "Total established connections: $connectionCount"
    Write-Output ""

    #Security Products
    Write-Output "[*] Security Products"

    # Check for AV
    $AV = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" -ErrorAction SilentlyContinue
    if ($AV) {
        Write-Output "AntiVirus: $($AV.displayName)"
        $global:AllResults += [PSCustomObject]@{
            Category = "Security Products"
            Item = "AntiVirus"
            Value = $AV.displayName
        }
    } else {
        Write-Output "AntiVirus: None detected"
        $global:AllResults += [PSCustomObject]@{
            Category = "Security Products"
            Item = "AntiVirus"
            Value = "None detected"
        }
    }

    # Check Firewall
    $HKLM = 2147483650
    $reg = get-wmiobject -list -namespace root\default | where-object { $_.name -eq "StdRegProv" }
    $firewallEnabled = $reg.GetDwordValue($HKLM, "System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile","EnableFirewall")
    $fwenabled = [bool]($firewallEnabled.uValue)

    Write-Output "Firewall: $(if($fwenabled){"Enabled"}else{"Disabled"})"
    $global:AllResults += [PSCustomObject]@{
        Category = "Security Products"
        Item = "Firewall"
        Value = if($fwenabled){"Enabled"}else{"Disabled"}
    }

    # Check for LAPS
    try {
        $lapsfile = Get-ChildItem "$env:ProgramFiles\LAPS\CSE\Admpwd.dll" -ErrorAction Stop
        Write-Output "LAPS: Installed"
        $global:AllResults += [PSCustomObject]@{
            Category = "Security Products"
            Item = "LAPS"
            Value = "Installed"
        }
    } catch {
        Write-Output "LAPS: Not installed"
        $global:AllResults += [PSCustomObject]@{
            Category = "Security Products"
            Item = "LAPS"
            Value = "Not installed"
        }
    }

    # Check for Sysmon
    try {
        $sysmondrv = Get-ChildItem "$env:SystemRoot\sysmondrv.sys" -ErrorAction Stop
        Write-Output "Sysmon: Installed (Version: $($sysmondrv.VersionInfo.FileVersion))"
        $global:AllResults += [PSCustomObject]@{
            Category = "Security Products"
            Item = "Sysmon"
            Value = "Installed (Version: $($sysmondrv.VersionInfo.FileVersion))"
        }
    } catch {
        Write-Output "Sysmon: Not installed"
        $global:AllResults += [PSCustomObject]@{
            Category = "Security Products"
            Item = "Sysmon"
            Value = "Not installed"
        }
    }
    Write-Output ""

    # Domain Checks (if not disabled)
    if ($DisableDomainChecks -eq $false) {
        Write-Output "[*] Domain Information"
        
        # Domain Controllers
        Try {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $DCS = $DomainObject.DomainControllers
            
            Write-Output "Domain Controllers:"
            foreach ($dc in $DCS) {
                Write-Output "- $($dc.Name)"
                $global:AllResults += [PSCustomObject]@{
                    Category = "Domain Information"
                    Item = "Domain Controller"
                    Value = $dc.Name
                }
            }
        } Catch {
            Write-Output "Unable to retrieve Domain Controllers."
        }
        
        # Domain Admins
        Try {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            
            $DAgroup = ([adsi]"WinNT://$domain/Domain Admins,group")
            $Members = @($DAgroup.psbase.invoke("Members"))
            [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
            
            Write-Output "Domain Admins:"
            foreach ($member in $MemberNames) {
                Write-Output "- $member"
                $global:AllResults += [PSCustomObject]@{
                    Category = "Domain Information"
                    Item = "Domain Admin"
                    Value = $member
                }
            }
        } Catch {
            Write-Output "Unable to retrieve Domain Admins."
        }
        Write-Output ""
    }

    # Port Scan (if enabled)
    If($Portscan) {
        if ($Portlist -ne "") {
            TCP-PortScan -Portlist $Portlist
        } else {
            TCP-PortScan -TopPorts $TopPorts
        }
    }

    # Handle CSV export
    If($ExportCSV) {
        try {
            # Create directory if it doesn't exist
            $directory = Split-Path -Path $defaultCSVPath -Parent
            if (!(Test-Path -Path $directory)) {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
                Write-Output "[*] Created directory: $directory"
            }
            
            # Export results to CSV
            $global:AllResults | Export-Csv -Path $defaultCSVPath -NoTypeInformation
            Write-Output "[*] Results exported to $defaultCSVPath"
        } catch {
            Write-Output "[!] Error exporting to CSV: $_"
        }
    }

    Write-Output "[+] Scan completed at $(Get-Date)"
}


function TCP-PortScan {
<#
.SYNOPSIS

Perform a full TCP connection scan to the destination hostname, or to 'allports.exposed' if that destination is not supplied.

Author: Joff Thyer, April 2014

.DESCRIPTION

TCP-Portscan is designed to perform a full TCP connection scan to the destination
hostname using either a port range of top X number of popular TCP ports.  The top
popular port list is derived from NMAP's services using the frequrency measurements
that appear in this file.  If the top X number of popular ports is not the desired
behavior, you can specify a minimum and maximum port number within which a range of
ports will be scanned.  By default, a random delay between 50 and 200 milliseconds
is added in order to assist in avoiding detection.  Also by default, if the hostname
is not specified then 'allports.exposed' will be used as a default.   The 'allports.exposed'
site responds to all TCP ports will the text of 'woot woot' if an HTTP request is sent,
but more to the point, all ports are considered open.

.PARAMETER Hostname

If provided, the hostname will be looked up and the resulting IP address used
as the IP address to be scanned.  If not provided, then the default hostname
of 'allports.exposed' will be used.

.PARAMETER MinPort

Specify the minimum port number in a range of ports to be scanned.

.PARAMETER MaxPort

Specify the maximum port number in a range of ports to be scanned.

.PARAMETER TopPorts

Specify the number of popular ports which you would like to be scanned.  Up to
128 ports may be specified.

.PARAMETER Timeout

Specify the TCP connection timeout in the range of 10 - 10000 milliseconds.

.PARAMETER NoRandomDelay

Disable the random delay between connection attempts.

#>

    param(  [String]$Hostname = 'allports.exposed',
            [ValidateRange(1,65535)][Int]$MinPort = 1,
            [ValidateRange(1,65535)][Int]$MaxPort = 1,
            [ValidateRange(1,128)][Int]$TopPorts = 50,
            [ValidateRange(10,10000)][Int]$Timeout = 400,
            [ValidateRange(1,65535)][String[]]$Portlist = "",
            [switch]$NoRandomDelay = $false )

    $resolved = [System.Net.Dns]::GetHostByName($Hostname)
    $ip = $resolved.AddressList[0].IPAddressToString

    # TopN port collection derived from NMAP project
    $tcp_top128 =  80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, `
135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, `
1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, `
8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, `
5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, `
2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, `
144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, `
3986, 13, 1029, 9, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, `
119, 37, 1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, `
6004, 1801, 19, 8031, 1041, 255, 3703, 17, 808, 3689, 1031, 1071, `
5901, 9102, 9000, 2105, 636, 1038, 2601, 7000

    $report = @()
    if ($MaxPort -gt 1 -and $MinPort -lt $MaxPort) {
        $ports = $MinPort..$MaxPort
        Write-Host -NoNewline "[*] Scanning $Hostname ($ip), port range $MinPort -> $MaxPort : "
    }
    elseif ($MaxPort -lt $MinPort) {
        Throw "Are you out of your mind?  Port range cannot go negative."
    }
    elseif($Portlist -ne ""){
    $ports = $Portlist
    Write-Host -NoNewline "[*] Scanning $Hostname ($ip), using the portlist provided."
    }
    else {
        $PortDiff = $TopPorts - 1
        $ports = $tcp_top128[0..$PortDiff]
        Write-Host -NoNewline "[*] Scanning $Hostname ($ip), top $TopPorts popular ports : "
    }
    
    $total = 0
    $tcp_count = 0
    foreach ($port in Get-Random -input $ports -count $ports.Count) {
        if (![Math]::Floor($total % ($ports.Count / 10))) {
            Write-Host -NoNewline "."
        }
        $total += 1
        $temp = "" | Select Address, Port, Proto, Status, Banner
        $temp.Proto = "tcp"
        $temp.Port = $port
        $temp.Address = $ip
        $tcp = new-Object system.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($ip,$port,$null,$null)
        $wait = $connect.AsyncWaitHandle.WaitOne($Timeout,$false)
        if (!$wait) {
            $error.clear()
            $tcp.cloase()
            $temp.Status = "closed"
        }
        else {
            try {
                $tcp.EndConnect($connect)
                $tcp.Close()
                $temp.Status = "open"
                $tcp_count += 1
            }
            catch {
                $temp.Status = "reset"
            }
        }
        $report += $temp

        # add random delay if we want it
        if (!$NoRandomDelay) {
            $sleeptime = Get-Random -Minimum 50 -Maximum 200
            Start-Sleep -Milliseconds $sleeptime
        }
    }
    Write-Host
    $columns = @{l='IP-Address';e={$_.Address}; w=15; a="left"},@{l='Proto';e={$_.Proto};w=5;a="right"},@{l='Port';e={$_.Port}; w=5; a="right"},@{l='Status';e={$_.Status}; w=4; a="right"}
    $report | where {$_.Status -eq "open"} | Sort-Object Port | Format-Table $columns -AutoSize
    Write-Output "[*] $tcp_count out of $total scanned ports are open!"
}
