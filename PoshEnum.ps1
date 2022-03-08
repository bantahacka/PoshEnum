### PoshEnum v0.1                            ###
### Enumeration script for Windows           ###
### Set execution policy to Bypass to run    ###
### TODO: Dump output to a writeable path    ###

function Test-IsAdmin
{
    # Function to test if script is being ran in an elevated shell. Returns True if elevated, otherwise False
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

Write-host "------------------------" -ForegroundColor Magenta;
Write-Host "| Welcome to PoshEnum! |" -ForegroundColor Magenta;
Write-host "------------------------" -ForegroundColor Magenta;
Write-Host " "

# Set buffer to 10000 Lines to allow scrollback
$buffer = $host.ui.RawUI.BufferSize;
$buffer.height = 10000;
$host.UI.RawUI.Set_BufferSize($buffer);

# Tell user if we are running in an elevated shell
if(Test-IsAdmin)
{
    Write-Host "
You are running in elevated mode. Detailed information will be available as a result." -ForegroundColor Green;
}
else
{
    Write-Host "
You are running in standard mode. Information may be limited." -ForegroundColor Red;
}

Write-Host " "
Write-host "-------------------------" -ForegroundColor Magenta;
Write-Host "| Local Machine Details |" -ForegroundColor Magenta;
Write-host "-------------------------" -ForegroundColor Magenta;
Write-Host " "

# Get Current User
Write-Host "
Current User: " -ForegroundColor Cyan; 
$user= [System.Security.Principal.WindowsIdentity]::GetCurrent().Name;
Write-Host $user; 

# Get User List
Write-Host "
User Information: " -ForegroundColor Cyan
Get-LocalUser | ft -AutoSize

# Get Group List
Write-Host "
Group Information: " -ForegroundColor Cyan
Get-LocalGroup | ft -AutoSize

# List Administrator Group Users
Write-Host "
List of users in Administrators: " -ForegroundColor Cyan
Get-LocalGroupMember -Group Administrators | ft -AutoSize

# Get system info
Write-Host "
System Information: " -ForegroundColor Cyan;
Get-ComputerInfo | fl; # TODO: Limit output to useful fields such as architecture, OS etc.

# Get running processes
Write-Host "
Running Processes: " -ForegroundColor Cyan;
if(Test-IsAdmin)
{
    Get-Process -IncludeUserName | Format-Table Name,UserName,Path -AutoSize;
}
else
{
    Get-Process | Format-Table Name,Path -AutoSize;
}

# Get services
Write-Host "
Running Services: " -ForegroundColor Cyan;
Get-WmiObject Win32_Service | Where-Object {$_.state -eq "Running"} | Format-Table @{L='Service Name';E={$_.Name}; Alignment='left'},@{L='Startup Type';E={$_.StartMode}; Alignment='left'},@{L='Process ID';E={$_.ProcessId}; Alignment='left'},@{L='Service Account';E={$_.StartName}; Alignment='left'},@{L='Path';E={$_.PathName}; Alignment='left'} -AutoSize;

# Get Scheduled Tasks
Write-Host "
Scheduled Tasks: " -ForegroundColor Cyan;
Get-ScheduledTask | ft TaskName,TaskPath,State,Description

Write-Host " "
Write-host "-------------------" -ForegroundColor Magenta;
Write-Host "| Network Details |" -ForegroundColor Magenta;
Write-host "-------------------" -ForegroundColor Magenta;
Write-Host " "

# Get network adapters
Write-Host "
Network Adapter Configuration: " -ForegroundColor Cyan;
Get-NetIPConfiguration | fl; # TODO: Get interface index into an array for later lookup

# Get ARP Cache
Write-Host "
ARP Cache: " -ForegroundColor Cyan
Get-NetNeighbor | ft IPAddress, LinkLayerAddress, State -AutoSize

# Get the routing table
Write-Host "
Routing Table: " -ForegroundColor Cyan;
Get-NetRoute | ft DestinationPrefix,NextHop,RouteMetric; 

# Check DNS entries by checking ipconfig /displaydns and %systemroot%\system32\drivers\etc\hosts
Write-Host " 
DNS Entries (Client Cache): " -ForegroundColor Cyan;
Get-DnsClientCache | Format-Table Entry,Data -AutoSize;
Write-Host "
DNS Entries (HOSTS file): 
" -ForegroundColor Cyan;
Get-Content -Path $env:SystemRoot\System32\drivers\etc\hosts;

# Get Network Shares for Local Machine
Write-Host "
Shares on this machine: " -ForegroundColor Cyan;
Get-WmiObject Win32_Share | ft -Autosize;

# Get Other Network Shares
Write-Host "
Network Machines (net view): " -ForegroundColor Cyan;
net view /all

Read-Host -Prompt "Press enter to exit..";
