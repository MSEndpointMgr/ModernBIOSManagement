<#
.SYNOPSIS
    Collect custom device inventory and upload to Log Analytics for further processing. 

.DESCRIPTION
    This script will collect device hardware and / or app inventory and upload this to a Log Analytics Workspace. This allows you to easily search in device hardware and installed apps inventory. 
    The script is meant to be runned on a daily schedule either via Proactive Remediations (RECOMMENDED) in Intune or manually added as local schedule task on your Windows 10 Computer. 

.EXAMPLE
    Invoke-CustomInventory.ps1 (Required to run as System or Administrator)      

.NOTES
    FileName:    Invoke-CustomInventory.ps1
    Author:      Jan Ketil Skanke
    Contributor: Sandy Zeng / Maurice Daly
    Contact:     @JankeSkanke
    Created:     2021-01-02
    Updated:     2021-09-08

    Version history:
    0.9.0 - (2021-01-02) Script created
    1.0.0 - (2021-01-02) Script polished cleaned up. 
    1.0.1 - (2021-04-05) Added NetworkAdapter array and fixed typo
    2.0   - (2021-08-29) Moved secrets out of code - now running via Azure Function 
    2.1   - (2021-09-08) Added section to cater for BIOS release version information, for HP, Dell and Lenovo.
#>
#region initialize
# Define your azure function URL: 
# Example 'https://<appname>.azurewebsites.net/api/<functioname>'
$AzureFunctionURL =

# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Control if you want to collect App or Device Inventory or both (True = Collect)
$CollectAppInventory = $true
$CollectDeviceInventory = $true
#Set Log Analytics Log Name

$AppLogName = "AppInventory"
$DeviceLogName = "DeviceInventory"

#endregion initialize

#region functions
# Function to get Azure AD DeviceID
function Get-AzureADDeviceID {
    <#
    .SYNOPSIS
        Get the Azure AD device ID from the local device.
    
    .DESCRIPTION
        Get the Azure AD device ID from the local device.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-05-26
        Updated:     2021-05-26
    
        Version history:
        1.0.0 - (2021-05-26) Function created
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
			if ($AzureADJoinCertificate -ne $null) {
				# Determine the device identifier from the subject name
				$AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
				# Handle return value
				return $AzureADDeviceID
			}
		}
	}
} #endfunction 

#Function to get AzureAD TenantID
function Get-AzureADTenantID {
	# Cloud Join information registry path
	$AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
	# Retrieve the child key name that is the tenant id for AzureAD
	$AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
	return $AzureADTenantID
}
# Function to download files (speedtest)
function Start-DownloadFile {
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$URL,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$Path,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	)
	Begin {
		# Construct WebClient object
		$WebClient = New-Object -TypeName System.Net.WebClient
	}
	Process {
		# Create path if it doesn't exist
		if (-not (Test-Path -Path $Path)) {
			New-Item -Path $Path -ItemType Directory -Force | Out-Null
		}
		
		# Start download of file
		$WebClient.DownloadFile($URL, (Join-Path -Path $Path -ChildPath $Name))
	}
	End {
		# Dispose of the WebClient object
		$WebClient.Dispose()
	}
} #endfunction
# Function to get all Installed Application
function Get-InstalledApplications() {
	param (
		[string]$UserSid
	)
	
	New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
	$regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
	$regpath += "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
	if (-not ([IntPtr]::Size -eq 4)) {
		$regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
		$regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
	}
	$propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString'
	$Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, PSPath | Sort-Object DisplayName
	Remove-PSDrive -Name "HKU" | Out-Null
	Return $Apps
}

function Start-PowerShellSysNative {
	param (
		[parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the sysnative PowerShell process.")]
		[ValidateNotNull()]
		[string]$Arguments
	)
	
	# Get the sysnative path for powershell.exe
	$SysNativePowerShell = Join-Path -Path ($PSHOME.ToLower().Replace("syswow64", "sysnative")) -ChildPath "powershell.exe"
	
	# Construct new ProcessStartInfo object to run scriptblock in fresh process
	$ProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
	$ProcessStartInfo.FileName = $SysNativePowerShell
	$ProcessStartInfo.Arguments = $Arguments
	$ProcessStartInfo.RedirectStandardOutput = $true
	$ProcessStartInfo.RedirectStandardError = $true
	$ProcessStartInfo.UseShellExecute = $false
	$ProcessStartInfo.WindowStyle = "Hidden"
	$ProcessStartInfo.CreateNoWindow = $true
	
	# Instatiate the new 64-bit process
	$Process = [System.Diagnostics.Process]::Start($ProcessStartInfo)
	
	# Read standard error output to determine if the 64-bit script process somehow failed
	$ErrorOutput = $Process.StandardError.ReadToEnd()
	if ($ErrorOutput) {
		Write-Error -Message $ErrorOutput
	}
} #endfunction
#endregion functions

#region script
#Get Common data for App and Device Inventory: 
#Get Intune DeviceID and ManagedDeviceName
if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
	$MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' }
	$ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)"
}
$ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
$ManagedDeviceID = $ManagedDeviceInfo.EntDMID
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

#Get Computer Info
$ComputerInfo = Get-ComputerInfo
$ComputerName = $ComputerInfo.CsName
$ComputerManufacturer = $ComputerInfo.CsManufacturer

#region DEVICEINVENTORY
if ($CollectDeviceInventory) {
	#Set Name of Log
	$DeviceLog = "DeviceInventory"
	
	#Get Intune DeviceID and ManagedDeviceName
	if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
		$MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' }
		$ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)"
	}
	$ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
	$ManagedDeviceID = $ManagedDeviceInfo.EntDMID
	
	#Get Windows Update Service Settings
	$DefaultAUService = (New-Object -ComObject "Microsoft.Update.ServiceManager").Services | Where-Object { $_.isDefaultAUService -eq $True } | Select-Object Name
	$AUMeteredNetwork = (Get-ItemProperty -Path HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings\).AllowAutoWindowsUpdateDownloadOverMeteredNetwork
	if ($AUMeteredNetwork -eq "0") {
		$AUMetered = "false"
	} else { $AUMetered = "true" }
	
	#Bandwitdh Checker 
	$SpeedTestExe = "$($env:SystemRoot)\temp\speedtest.exe"
	if ((Test-Path -Path $SpeedTestExe) -eq $false) {
		#Download and extract Speedtest Cli
		try {
			$SpeedtestURL = "https://www.speedtest.net/apps/cli"
			$WebResponseURL = ((Invoke-WebRequest -Uri $SpeedtestURL -UseBasicParsing -ErrorAction Stop -Verbose:$false).links | Where-Object { $_.outerHTML -like "*Download for Windows*" }).href
			$SpeedtestcliFilename = Split-Path -Path $WebResponseURL -Leaf
			Start-DownloadFile -URL $WebResponseURL -Path "$($env:SystemRoot)\temp" -Name $SpeedtestcliFilename
			Expand-Archive "$($env:SystemRoot)\temp\$($SpeedtestcliFilename)" -DestinationPath "$($env:SystemRoot)\temp" -Force -ErrorAction Stop
		} catch {
			#Failed to download 
			$SpeedTestExe = $null
		}
	}
	if ($SpeedTestExe -ne $null) {
		$SpeedtestResults = & $SpeedTestExe --format=json --accept-license --accept-gdpr | ConvertFrom-Json
		if (-not ([string]::IsNullOrEmpty($SpeedtestResults.download))) {
			$DownloadSpeedMbps = [math]::Round($SpeedtestResults.download.bandwidth / 1000000 * 8, 2)
			$UploadSpeedSpeedMbps = [math]::Round($SpeedtestResults.upload.bandwidth / 1000000 * 8, 2)
			$NetLatencySec = [math]::Round($SpeedtestResults.ping.latency)
		} else {
			$DownloadSpeedMbps = 0
			$UploadSpeedSpeedMbps = 0
			$NetLatencySec = 0
		}
	} else {
		$DownloadSpeedMbps = 0
		$UploadSpeedSpeedMbps = 0
		$NetLatencySec = 0
	}
	
	#Get Device Location
	$ComputerPublicIP = (Invoke-WebRequest -UseBasicParsing -Uri "http://ifconfig.me/ip").Content
	$Computerlocation = Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$ComputerPublicIP"
	$ComputerCountry = $Computerlocation.country
	$ComputerCity = $Computerlocation.city
	
	# Get Computer Inventory Information 
	$ComputerModel = $ComputerInfo.CsModel
	$ComputerUptime = [int]($ComputerInfo.OsUptime).Days
	$ComputerLastBoot = $ComputerInfo.OsLastBootUpTime
	$ComputerInstallDate = $ComputerInfo.OsInstallDate
	$ComputerWindowsVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name "DisplayVersion").DisplayVersion
	$ComputerSystemSkuNumber = $ComputerInfo.CsSystemSKUNumber
	$ComputerSerialNr = $ComputerInfo.BiosSeralNumber
	$ComputerBiosUUID = Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
	$ComputerBiosVersion = $ComputerInfo.BiosSMBIOSBIOSVersion
	$ComputerBiosDate = $ComputerInfo.BiosReleaseDate
	$ComputerFirmwareType = $ComputerInfo.BiosFirmwareType
	$ComputerPCSystemType = $ComputerInfo.CsPCSystemType
	$ComputerPCSystemTypeEx = $ComputerInfo.CsPCSystemTypeEx
	$ComputerPhysicalMemory = [Math]::Round(($ComputerInfo.CsTotalPhysicalMemory / 1GB))
	$ComputerOSBuild = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
	$ComputerOSRevision = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
	$ComputerCPU = Get-CimInstance win32_processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors
	$ComputerProcessorManufacturer = $ComputerCPU.Manufacturer | Get-Unique
	$ComputerProcessorName = $ComputerCPU.Name | Get-Unique
	$ComputerNumberOfCores = $ComputerCPU.NumberOfCores | Get-Unique
	$ComputerNumberOfLogicalProcessors = $ComputerCPU.NumberOfLogicalProcessors | Get-Unique
	$TPMValues = Get-Tpm -ErrorAction SilentlyContinue | Select-Object -Property TPMReady, TPMPresent, TPMEnabled, TPMActivated, ManagedAuthLevel
	$BitLockerInfo = Get-BitLockerVolume -MountPoint C: | Select-Object -Property *
	$ComputerTPMReady = $TPMValues.TPMReady
	$ComputerTPMPresent = $TPMValues.TPMPresent
	$ComputerTPMEnabled = $TPMValues.TPMEnabled
	$ComputerTPMActivated = $TPMValues.TPMActivated
	$ComputerTPMThumbprint = (Get-TpmEndorsementKeyInfo).AdditionalCertificates.Thumbprint
	$ComputerBitlockerCipher = $BitLockerInfo.EncryptionMethod
	$ComputerBitlockerStatus = $BitLockerInfo.VolumeStatus
	$ComputerBitlockerProtection = $BitLockerInfo.ProtectionStatus
	$ComputerDefaultAUService = $DefaultAUService.Name
	$ComputerAUMetered = $AUMetered
	
	# Get BIOS information
	# Determine manufacturer specific information
	switch -Wildcard ($ComputerManufacturer) {
		"*Microsoft*" {
			$ComputerManufacturer = "Microsoft"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$SystemSKU = Get-WmiObject -Namespace root\wmi -Class MS_SystemInformation | Select-Object -ExpandProperty SystemSKU
		}
		"*HP*" {
			$ComputerManufacturer = "Hewlett-Packard"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$SystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct.Trim()
		}
		"*Hewlett-Packard*" {
			$ComputerManufacturer = "Hewlett-Packard"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$SystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct.Trim()
			
			# Obtain current BIOS release
			$CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
			
			# Detect new versus old BIOS formats
			switch -wildcard ($($CurrentBIOSProperties.SMBIOSBIOSVersion)) {
				"*ver*" {
					if ($CurrentBIOSProperties.SMBIOSBIOSVersion -match '.F.\d+$') {
						$ComputerBiosVersion = ($CurrentBIOSProperties.SMBIOSBIOSVersion -split "Ver.")[1].Trim()
					} else {
						$ComputerBiosVersion = [System.Version]::Parse(($CurrentBIOSProperties.SMBIOSBIOSVersion).TrimStart($CurrentBIOSProperties.SMBIOSBIOSVersion.Split(".")[0]).TrimStart(".").Trim().Split(" ")[0])
					}
				}
				default {
					$ComputerBiosVersion = "$($CurrentBIOSProperties.SystemBiosMajorVersion).$($CurrentBIOSProperties.SystemBiosMinorVersion)"
				}
			}
			
		}
		"*Dell*" {
			$ComputerManufacturer = "Dell"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$SystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku.Trim()
			
			# Obtain current BIOS release
			$ComputerBiosVersion = (Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
			
		}
		"*Lenovo*" {
			$ComputerManufacturer = "Lenovo"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version).Trim()
			$SystemSKU = ((Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).SubString(0, 4)).Trim()
			
			# Obtain current BIOS release
			$ComputerBiosVersion = ((Get-WmiObject -Class Win32_BIOS | Select-Object -Property *).ReleaseDate).SubString(0, 8)
		}
	}
		
	#$timestamp = Get-Date -Format "yyyy-MM-DDThh:mm:ssZ" 
	
	#Get network adapters
	$NetWorkArray = @()
	
	$CurrentNetAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
	
	foreach ($CurrentNetAdapter in $CurrentNetAdapters) {
		$IPConfiguration = Get-NetIPConfiguration -InterfaceIndex $CurrentNetAdapter[0].ifIndex
		$ComputerNetInterfaceDescription = $CurrentNetAdapter.InterfaceDescription
		$ComputerNetProfileName = $IPConfiguration.NetProfile.Name
		$ComputerNetIPv4Adress = $IPConfiguration.IPv4Address.IPAddress
		$ComputerNetInterfaceAlias = $CurrentNetAdapter.InterfaceAlias
		$ComputerNetIPv4DefaultGateway = $IPConfiguration.IPv4DefaultGateway.NextHop
		
		$tempnetwork = New-Object -TypeName PSObject
		$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetInterfaceDescription" -Value "$ComputerNetInterfaceDescription" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetProfileName" -Value "$ComputerNetProfileName" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetIPv4Adress" -Value "$ComputerNetIPv4Adress" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetInterfaceAlias" -Value "$ComputerNetInterfaceAlias" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetIPv4DefaultGateway" -Value "$ComputerNetIPv4DefaultGateway" -Force
		$NetWorkArray += $tempnetwork
	}
	[System.Collections.ArrayList]$NetWorkArrayList = $NetWorkArray
	
	# Create JSON to Upload to Log Analytics
	$Inventory = New-Object System.Object
	$Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Model" -Value "$ComputerModel" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value "$ComputerManufacturer" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "PCSystemType" -Value "$ComputerPCSystemType" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "PCSystemTypeEx" -Value "$ComputerPCSystemTypeEx" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerUpTime" -Value "$ComputerUptime" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "LastBoot" -Value "$ComputerLastBoot" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value "$ComputerInstallDate" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "WindowsVersion" -Value "$ComputerWindowsVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "DefaultAUService" -Value "$ComputerDefaultAUService" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "AUMetered" -Value "$ComputerAUMetered" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SystemSkuNumber" -Value "$ComputerSystemSkuNumber" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value "$ComputerSerialNr" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SMBIOSUUID" -Value "$ComputerBiosUUID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BiosVersion" -Value "$ComputerBiosVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BiosDate" -Value "$ComputerBiosDate" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "FirmwareType" -Value "$ComputerFirmwareType" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Memory" -Value "$ComputerPhysicalMemory" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSBuild" -Value "$ComputerOSBuild" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSRevision" -Value "$ComputerOSRevision" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUManufacturer" -Value "$ComputerProcessorManufacturer" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUName" -Value "$ComputerProcessorName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUCores" -Value "$ComputerNumberOfCores" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPULogical" -Value "$ComputerNumberOfLogicalProcessors" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMReady" -Value "$ComputerTPMReady" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMPresent" -Value "$ComputerTPMPresent" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMEnabled" -Value "$ComputerTPMEnabled" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMActived" -Value "$ComputerTPMActivated" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMThumbprint" -Value "$ComputerTPMThumbprint" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerCipher" -Value "$ComputerBitlockerCipher" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerVolumeStatus" -Value "$ComputerBitlockerStatus" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerProtectionStatus" -Value "$ComputerBitlockerProtection" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerCountry" -Value "$ComputerCountry" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerCity" -Value "$ComputerCity" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value $NetWorkArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "DownloadSpeedMbps" -Value $DownloadSpeedMbps -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "UploadSpeedSpeedMbps" -Value $UploadSpeedSpeedMbps -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "NetLatencySec" -Value $NetLatencySec -Force
	
	
    <#$DevicePayLoad = [PSCustomObject]@{
        Type = "DeviceInventory"
        AzureADDeviceID = $AzureADDeviceID
        AzureADTenantID = $AzureADTenantID
        Payload = $Inventory
    }#>
	$DevicePayLoad = $Inventory
	
	#$DeviceJson = $DevicePayLoad | ConvertTo-Json -Depth 9
	
	
}
#endregion DEVICEINVENTORY

#region APPINVENTORY
if ($CollectAppInventory) {
	#$AppLog = "AppInventory"
	
	#Get SID of current interactive users
	$CurrentLoggedOnUser = (Get-CimInstance win32_computersystem).UserName
	$AdObj = New-Object System.Security.Principal.NTAccount($CurrentLoggedOnUser)
	$strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
	$UserSid = $strSID.Value
	#Get Apps for system and current user
	$MyApps = Get-InstalledApplications -UserSid $UserSid
	$UniqueApps = ($MyApps | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedApps = ($MyApps | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateApp = ($DuplicatedApps | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppList = $UniqueApps + $NewestDuplicateApp | Sort-Object DisplayName
	
	$AppArray = @()
	foreach ($App in $CleanAppList) {
		$tempapp = New-Object -TypeName PSObject
		$tempapp | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppName" -Value $App.DisplayName -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppVersion" -Value $App.DisplayVersion -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppInstallDate" -Value $App.InstallDate -Force -ErrorAction SilentlyContinue
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppPublisher" -Value $App.Publisher -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallString" -Value $App.UninstallString -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallRegPath" -Value $app.PSPath.Split("::")[-1]
		$AppArray += $tempapp
	}
	
    <#$AppPayLoad = [PSCustomObject]@{
        Type = "AppInventory"
        AzureADDeviceID = "12312"
        AzureADTenantID = $AzureADTenantID
        Payload = $AppArray
    }#>
	
	$AppPayLoad = $AppArray
	
	#$Appjson | Out-File C:\Temp\apppayload.json
    <#
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    try{
        $ResponseAppInventory = Invoke-RestMethod $AzureFunctionURL -Method 'POST' -Headers $headers -Body $Appjson
    } catch {
        $ResponseAppInventory = "StatusCode: $($_.Exception.Response.StatusCode.value__)" 
    }#>
}
#endregion APPINVENTORY

#Randomize over 50 50 minutes 
$ExecuteInSeconds = (Get-Random -Maximum 3000 -Minimum 1)
Start-Sleep -Seconds $ExecuteInSeconds

#Report back status
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

$PayLoad = [PSCustomObject]@{
	AppLogName	    = $AppLogName
	DeviceLogName   = $DeviceLogName
	AzureADTenantID = $AzureADTenantID
	AzureADDeviceID = $AzureADDeviceID
	AppPayload	    = $AppPayload
	DevicePayload   = $DevicePayload
}

$PayloadJSON = $PayLoad | ConvertTo-Json -Depth 9

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

try {
	$ResponseInventory = Invoke-RestMethod $AzureFunctionURL -Method 'POST' -Headers $headers -Body $PayloadJSON
} catch {
	$ResponseInventory = "StatusCode: $($_.Exception.Response.StatusCode.value__)"
}

$AppResponse = $ResponseInventory.Split(",") | Where-Object { $_ -match "App:" }
$DeviceResponse = $ResponseInventory.Split(",") | Where-Object { $_ -match "Device:" }


if ($CollectDeviceInventory) {
	if ($DeviceResponse -match "Device:200") {
		
		$OutputMessage = $OutPutMessage + "DeviceInventory:OK " + $DeviceResponse
	} else {
		$OutputMessage = $OutPutMessage + "DeviceInventory:Fail " + $DeviceResponse
	}
}
if ($CollectAppInventory) {
	if ($AppResponse -match "App:200") {
		
		$OutputMessage = $OutPutMessage + " AppInventory:OK " + $AppResponse
	} else {
		$OutputMessage = $OutPutMessage + " AppInventory:Fail " + $AppResponse
	}
}



Write-Output $OutputMessage
if (($DeviceResponse -notmatch "Device:200") -or ($AppResponse -notmatch "App:200")) {
	Exit 1
} else {
	Exit 0
}

#endregion script
