# If your LogRhythm Agent runs as a user other than NT AUTHORITY\SYSTEM, put that in the variable below:
# EG MYDOMAIN\LogRhythm
$agent_user = ''

#Requires -RunAsAdministrator

$path       = 'C:\LogRhythm\logrhythm-sigsci'

##### Create our scheduled task #####
$executable = "py -3 $path\logrhythm-sigsci.py"
$taskName   = 'Download SigSci logs for LogRhythm'

$action   = New-ScheduledTaskAction -Execute py -Argument "-3 $path\logrhythm-sigsci.py"
$trigger  = New-ScheduledTaskTrigger -At (Get-Date).Date -Once -RepetitionInterval (New-TimeSpan -Minutes 5)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 4)

try {
  Register-ScheduledTask -ErrorAction Stop -TaskName $taskName -Trigger $trigger -Action $action -Setting $settings -User "NT AUTHORITY\SYSTEM" -RunLevel 1
} catch {
  Write-Host "Scheduled task already exists, skipping."
}
Set-ScheduledTask $taskName -Trigger $trigger

##### Install to our permanent home #####
# Configure script directory
if (!(Test-Path ($path))) {
  New-Item -Path $path -ItemType directory
  New-Item -Path $path\logs -ItemType directory
}
# Copy things over to the new location
$robocopy_args = "/e"
if (Test-Path ("$path\sigsci.conf")) {
  $robocopy_args += " /xf sigsci.conf"
}
$source = (Get-Item $PSScriptRoot).parent.Fullname
robocopy $source $path $robocopy_args

##### Lock down ACL's #####
$acl = get-acl $path
# Disable and delete inheritance
$acl.SetAccessRuleProtection($true,$false)

# SYSTEM can read and execute
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM', "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($AccessRule)

# Admins can read and modify
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', "Read,Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($AccessRule)

# LogRhythm agent gets read
if ($agent_user) {
  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($agent_user, "ReadAndExecute", "None", "None", "Allow")
  $acl.SetAccessRule($AccessRule)
}

$acl | Set-Acl $path


# Configure logs directory
$acl = get-acl "$path\logs"

#SYSTEM can write logs
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM', "Read,Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($AccessRule)

#LogRhythm agent can write logs
if ($agent_user) {
  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($agent_user, "Read,Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
  $acl.SetAccessRule($AccessRule)
}

$acl | Set-Acl "$path\logs"

##### Fire up wordpad to edit sigsci.conf #####
Start-Process -FilePath "$($env:Programfiles)\Windows NT\Accessories\wordpad.exe" -ArgumentList "$path\sigsci.conf"
