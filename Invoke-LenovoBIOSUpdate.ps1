<#
.SYNOPSIS
	Invoke Lenovo BIOS Update process.

.DESCRIPTION
	This script will invoke the Lenovo BIOS update process for the executable residing in the path specified for the Path parameter.

	IMPORTANT: This script requires the WinPE-HTA optional component added to the boot image when used during WinPE phase.

.PARAMETER Path
	Specify the path containing the WinUPTP or Flash.cmd

.PARAMETER Password
	Specify the BIOS password if necessary.

.PARAMETER LogFileName
	Set the name of the log file produced by the flash utility.

.EXAMPLE
	.\Invoke-LenovoBIOSUpdate.ps1 -Path %OSDBIOSPackage01% -Password "BIOSPassword"

.NOTES
    FileName:    Invoke-LenovoBIOSUpdate.ps1
    Author:      Maurice Daly / Nickolaj Andersen
    Contact:     @modaly_it / @NickolajA
    Created:     2017-06-09
    Updated:     2019-05-14

    Version history:
    1.0.0 - (2017-06-09) Script created
	1.0.1 - (2017-07-05) Added additional logging, methods and variables
	1.0.2 - (2018-01-29) Changed condition for the password switches
	1.0.3 - (2018-04-30) Example conditional variable example updated. No functional changes
	1.0.4 - (2018-05-07) Updated to copy in required OLEDLG.dll where missing in the BIOS package
	1.0.5 - (2018-05-08) Updated to cater for varying OS source directory paths
	1.0.6 - (2018-12-10) Updated to support 64-bit version of Flash64.cmd
	1.0.7 - (2019-05-01) Extended the search for OLEDLG.dll to include X: for when running from WinPE
	1.0.8 - (2019-05-01) Fixed a bug where the script would show an error and fail if the WinUPTP log file could not be found
	1.0.9 - (2019-05-14) Handle $Password to check if empty string or null instead of just null value
#>
[CmdletBinding()]
param (
	[parameter(Mandatory = $true, HelpMessage = "Specify the path containing the Flash64W.exe and BIOS executable.")]
	[ValidateNotNullOrEmpty()]
	[string]$Path,
	[parameter(Mandatory = $false, HelpMessage = "Specify the BIOS password if necessary.")]
	[ValidateNotNullOrEmpty()]
	[string]$Password,
	[parameter(Mandatory = $false, HelpMessage = "Set the name of the log file produced by the flash utility.")]
	[ValidateNotNullOrEmpty()]
	[string]$LogFileName = "LenovoFlashBiosUpdate.log"
)
Begin {
	# Load Microsoft.SMS.TSEnvironment COM object
	try {
		$TSEnvironment = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop
	}
	catch [System.Exception] {
		Write-Warning -Message "Unable to construct Microsoft.SMS.TSEnvironment object"
	}
}
Process {
	$LogsDirectory = Join-Path -Path $env:SystemRoot -ChildPath "Temp"
	$LogDirectoryPath = if ($null -ne $TSEnvironment) { $TSEnvironment.Value("_SMSTSLogPath") } else { $null }
	if ([string]::IsNullOrEmpty($LogDirectoryPath)) {
		$LogDirectoryPath = $LogsDirectory
	}

	# Functions
	function Write-CMLogEntry {
		param (
			[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
			[ValidateNotNullOrEmpty()]
			[string]$Value,
			[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
			[ValidateNotNullOrEmpty()]
			[ValidateSet("1", "2", "3")]
			[string]$Severity,
			[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
			[ValidateNotNullOrEmpty()]
			[string]$FileName = "Invoke-LenovoBIOSUpdate.log"
		)
		# Determine log file location
		$LogFilePath = Join-Path -Path $LogDirectoryPath -ChildPath $FileName

		# Construct time stamp for log entry
		$Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-CimInstance -ClassName Win32_TimeZone | Select-Object -ExpandProperty Bias))

		# Construct date for log entry
		$Date = (Get-Date -Format "MM-dd-yyyy")

		# Construct context for log entry
		$Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

		# Construct final log entry
		$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""LenovoBIOSUpdate.log"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

		# Add value to log file
		try {
			Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
		}

		catch [System.Exception] {
			Write-Warning -Message "Unable to append log entry to Invoke-LenovoBIOSUpdate.log file. Error message: $($_.Exception.Message)"
		}
	}

	function Enable-BitLockerProtection {
		if ($Script:BitLockerSuspendedByScript -ne $true) {
			return $true
		}

		Write-CMLogEntry -Value "Re-enabling BitLocker protection on volume: $($env:SystemDrive)" -Severity 1
		Manage-Bde -Protectors -Enable $env:SystemDrive | Out-Null
		if ($LASTEXITCODE -ne 0) {
			Write-CMLogEntry -Value "Failed to re-enable BitLocker protection on volume $($env:SystemDrive). Manage-Bde returned exit code $($LASTEXITCODE)." -Severity 3
			return $false
		}

		try {
			$Volume = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" -ErrorAction Stop | Where-Object { $_.DriveLetter -eq $env:SystemDrive }
			if (($null -eq $Volume) -or ($Volume.ProtectionStatus -ne 1)) {
				Write-CMLogEntry -Value "BitLocker protection did not return to the protected state on volume $($env:SystemDrive)." -Severity 3
				return $false
			}
		}
		catch [System.Exception] {
			Write-CMLogEntry -Value "Unable to verify that BitLocker protection was re-enabled on volume $($env:SystemDrive). Error message: $($_.Exception.Message)" -Severity 3
			return $false
		}

		$Script:BitLockerSuspendedByScript = $false
		return $true
	}

	# A virtual machine has no physical firmware flash chip. The guest BIOS/UEFI is a software template
	# owned by the hypervisor, so vendor flash utilities refuse to execute and fail the task sequence.
	# Skip gracefully instead.
	try {
		$ComputerSystems = @(Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop)
	}
	catch [System.Exception] {
		Write-CMLogEntry -Value "Unable to inventory the computer platform safely. BIOS update is blocked. Error message: $($_.Exception.Message)" -Severity 3
		exit 1
	}
	if (($ComputerSystems.Count -ne 1) -or [string]::IsNullOrWhiteSpace([string]$ComputerSystems[0].Model) -or [string]::IsNullOrWhiteSpace([string]$ComputerSystems[0].Manufacturer)) {
		Write-CMLogEntry -Value "Computer platform inventory did not return one complete system identity. BIOS update is blocked." -Severity 3
		exit 1
	}
	$ComputerSystem = $ComputerSystems[0]
	$VirtualMachineModels = @("Virtual Machine", "VMware Virtual Platform", "VMware7,1", "VMware20,1", "VMware Virtual Platform None", "VirtualBox", "HVM domU", "KVM", "QEMU Virtual Machine", "Standard PC (Q35 + ICH9, 2009)", "Standard PC (i440FX + PIIX, 1996)", "Parallels Virtual Platform", "Google Compute Engine", "AHV")
	if (($ComputerSystem.Model -in $VirtualMachineModels) -or ($ComputerSystem.Manufacturer -match "VMware|QEMU|innotek|Xen|Parallels|Nutanix|Red Hat|Google|Amazon EC2|OpenStack")) {
		Write-CMLogEntry -Value "Virtual machine detected ('$($ComputerSystem.Manufacturer) $($ComputerSystem.Model)'). BIOS/UEFI firmware is managed by the hypervisor, skipping BIOS flash" -Severity 2
		exit 0
	}

	Set-Location -Path $Path
	# Write log file for script execution
	Write-CMLogEntry -Value "Initiating script to determine flashing capabilities for Lenovo BIOS updates" -Severity 1

	# Check for required DLL's
	if ((Test-Path -Path (Join-Path -Path $Path -ChildPath "OLEDLG.dll")) -eq $False) {
		Write-CMLogEntry -Value "Copying OLEDLG.dll to $($Path) directory" -Severity 1

		# Build an ordered list of candidate source locations. Previously the OSDisk branch was an
		# independent if-statement, so when OSDisk was populated but did not contain the DLL the
		# remaining fallbacks were never evaluated and the missing DLL went unreported.
		$OLEDLGCandidates = New-Object -TypeName System.Collections.ArrayList
		if (($null -ne $TSEnvironment) -and (([string]::IsNullOrEmpty($TSEnvironment.Value("OSDisk"))) -eq $false)) {
			$OLEDLGCandidates.Add((Join-Path -Path $TSEnvironment.Value("OSDisk") -ChildPath "Windows\System32\OLEDLG.dll")) | Out-Null
		}
		foreach ($DriveLetter in @("C:", "D:", "X:")) {
			$OLEDLGCandidates.Add("$($DriveLetter)\Windows\System32\OLEDLG.dll") | Out-Null
		}

		$OLEDLGSource = $OLEDLGCandidates | Where-Object { Test-Path -Path $_ } | Select-Object -First 1
		if (-not([string]::IsNullOrEmpty($OLEDLGSource))) {
			Copy-Item -Path $OLEDLGSource -Destination "$($Path)\OLEDLG.dll"
		}
		else {
			Write-CMLogEntry -Value "Failed to copy DLL file. Aborting update process" -Severity 3; exit 1
		}
	}

	# WinUPTP bios upgrade utility file name
	# NOTE: -First 1 is required, a recursive search can return multiple matches which would
	# otherwise produce an array and corrupt the -FilePath argument passed to Start-Process.
	if (([Environment]::Is64BitOperatingSystem) -eq $true) {
		$WinUPTPUtility = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "WinUPTP64.exe"	} | Select-Object -First 1 -ExpandProperty FullName
	}
	else {
		$WinUPTPUtility = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "WinUPTP.exe" } | Select-Object -First 1 -ExpandProperty FullName
	}

	# Flash CMD upgrade utility file name
	if (([Environment]::Is64BitOperatingSystem) -eq $true) {
		$FlashCMDUtility = Get-ChildItem -Path $Path -Filter "*.cmd" -Recurse | Where-Object { $_.Name -like "Flash64.cmd" } | Select-Object -First 1 -ExpandProperty FullName
	}
	else {
		$FlashCMDUtility = Get-ChildItem -Path $Path -Filter "*.cmd" -Recurse | Where-Object { $_.Name -like "Flash.cmd" } | Select-Object -First 1 -ExpandProperty FullName
	}

	# Select a single update method. These were previously two independent if-statements, which meant
	# that a package shipping both utilities would silently fall through to Flash.cmd while having
	# already logged that WinUPTP would be used.
	if (-not([string]::IsNullOrEmpty($WinUPTPUtility))) {
		# Set required switches for silent upgrade of the bios and logging
		Write-CMLogEntry -Value "Using WinUPTP BIOS update method" -Severity 1
		$FlashSwitches = " /S"
		$FlashUtility = $WinUPTPUtility
	}
	elseif (-not([string]::IsNullOrEmpty($FlashCMDUtility))) {
		# Set required switches for silent upgrade of the bios and logging
		Write-CMLogEntry -Value "Using FlashCMDUtility BIOS update method" -Severity 1
		$FlashSwitches = " /quiet /sccm /ign"
		$FlashUtility = $FlashCMDUtility
	}

	if (-not($FlashUtility)) {
		Write-CMLogEntry -Value "Supported upgrade utility was not found." -Severity 3; exit 1
	}

	if (-not([System.String]::IsNullOrEmpty($Password))) {
		# Add password to the flash bios switches
		$FlashSwitches = $FlashSwitches + " /pass:$($Password)"
		# Escape the password before using it as a regular expression pattern, otherwise a password
		# containing regex meta characters would either fail to be masked or throw a parsing error.
		Write-CMLogEntry -Value "Using the following switches for BIOS file: $($FlashSwitches -replace [regex]::Escape($Password), "<Password Removed>")" -Severity 1
	}
	else {
		Write-CMLogEntry -Value "Using the following switches for BIOS file: $($FlashSwitches)" -Severity 1
	}

	# Set log file location
	$LogFilePath = Join-Path -Path $LogDirectoryPath -ChildPath $LogFileName

	if (($TSEnvironment -ne $null) -and ($TSEnvironment.Value("_SMSTSinWinPE") -eq $true)) {
		try {
			# Start flash update process
			Write-CMLogEntry -Value "Running Flash Update - $($FlashUtility)" -Severity 1
			$FlashProcess = Start-Process -FilePath $FlashUtility -ArgumentList "$FlashSwitches" -Passthru -Wait -ErrorAction Stop
			$FlashExitCode = $FlashProcess.ExitCode

			# Output Exit Code for testing purposes
			$FlashExitCode | Out-File -FilePath $LogFilePath

			# Get winuptp.log file. Scoped to the package path and limited to the first match, since
			# multiple results would previously be passed to Copy-Item as an array.
			$WinUPTPLog = Get-ChildItem -Path $Path -Filter "winuptp.log" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
			if (-not([string]::IsNullOrEmpty($WinUPTPLog))) {
				Write-CMLogEntry -Value "winuptp.log file path is $($WinUPTPLog)" -Severity 1
				$SMSTSLogPath = Join-Path -Path $LogDirectoryPath -ChildPath "winuptp.log"
				Copy-Item -Path $WinUPTPLog -Destination $SMSTSLogPath -Force -ErrorAction SilentlyContinue
			}

			# Evaluate the exit code. Previously it was only written to a file and never acted upon,
			# so a failed flash would still report the step as successful.
			switch ($FlashExitCode) {
				0 {
					Write-CMLogEntry -Value "BIOS update completed with exit code $($FlashExitCode). A restart is required to apply the update" -Severity 1
					if ($TSEnvironment -ne $null) {
						$TSEnvironment.Value("SMSTSBIOSUpdateRebootRequired") = "True"
					}
				}
				1073807364 {
					Write-CMLogEntry -Value "BIOS update returned undocumented exit code $($FlashExitCode) (0x3FFF0004). The update outcome cannot be verified; review winuptp.log." -Severity 3
					exit 1
				}
				default {
					Write-CMLogEntry -Value "BIOS update failed with exit code $($FlashExitCode)" -Severity 3; exit $FlashExitCode
				}
			}
		}
		catch [System.Exception] {
			Write-CMLogEntry -Value "An error occured while updating the system BIOS in WinPE phase. Error message: $($_.Exception.Message)" -Severity 3; exit 1
		}
	}
	else {
		# Detect BitLocker status for the operating system volume using CIM instead of parsing
		# localized manage-bde console output, which is unreliable on non-English systems.
		try {
			$OSVolumes = @(Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" -ErrorAction Stop | Where-Object { $_.DriveLetter -eq $env:SystemDrive })
		}
		catch [System.Exception] {
			Write-CMLogEntry -Value "Unable to determine BitLocker status for volume $($env:SystemDrive). BIOS update is blocked. Error message: $($_.Exception.Message)" -Severity 3
			exit 1
		}
		if (($OSVolumes.Count -ne 1) -or ($OSVolumes[0].ProtectionStatus -notin @(0, 1))) {
			Write-CMLogEntry -Value "BitLocker inventory did not return one supported protection state for volume $($env:SystemDrive). BIOS update is blocked." -Severity 3
			exit 1
		}
		$OSVolume = $OSVolumes[0]
		$OSVolumeEncrypted = $OSVolume.ProtectionStatus -eq 1

		# Suspend BitLocker if the operating system volume is protected
		if ($OSVolumeEncrypted -eq $true) {
			Write-CMLogEntry -Value "Suspending BitLocker protected volume: $($env:SystemDrive)" -Severity 1
			Manage-Bde -Protectors -Disable $env:SystemDrive -RebootCount 1 | Out-Null
			if ($LASTEXITCODE -ne 0) {
				Write-CMLogEntry -Value "Failed to suspend BitLocker protection on volume $($env:SystemDrive). Manage-Bde returned exit code $($LASTEXITCODE)." -Severity 3; exit 1
			}
			$Script:BitLockerSuspendedByScript = $true

			# Verify that protection was actually suspended before flashing, a failed suspension
			# combined with a BIOS update can leave the device requiring the recovery key
			try {
				$OSVolume = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" -ErrorAction Stop | Where-Object { $_.DriveLetter -eq $env:SystemDrive }
			}
			catch [System.Exception] {
				Write-CMLogEntry -Value "Unable to verify BitLocker suspension on volume $($env:SystemDrive). Error message: $($_.Exception.Message)" -Severity 3
				$null = Enable-BitLockerProtection
				exit 1
			}
			if (($OSVolume -eq $null) -or ($OSVolume.ProtectionStatus -ne 0)) {
				Write-CMLogEntry -Value "Failed to suspend BitLocker protection on volume $($env:SystemDrive), aborting BIOS update to prevent a recovery key prompt" -Severity 3
				$null = Enable-BitLockerProtection
				exit 1
			}
		}

		# Start BIOS update process
		try {
			Write-CMLogEntry -Value "Running Flash Update - $($FlashUtility)" -Severity 1
			$FlashProcess = Start-Process -FilePath $FlashUtility -ArgumentList "$($FlashSwitches)" -Passthru -Wait -ErrorAction Stop
			$FlashExitCode = $FlashProcess.ExitCode

			# Output Exit Code for testing purposes
			$FlashExitCode | Out-File -FilePath $LogFilePath

			# Evaluate the exit code instead of assuming success
			switch ($FlashExitCode) {
				0 {
					Write-CMLogEntry -Value "BIOS update completed with exit code $($FlashExitCode). A restart is required to apply the update" -Severity 1
					if ($TSEnvironment -ne $null) {
						$TSEnvironment.Value("SMSTSBIOSUpdateRebootRequired") = "True"
					}
				}
				1073807364 {
					Write-CMLogEntry -Value "BIOS update returned undocumented exit code $($FlashExitCode) (0x3FFF0004). The update outcome cannot be verified; review winuptp.log." -Severity 3
					$null = Enable-BitLockerProtection
					exit 1
				}
				default {
					Write-CMLogEntry -Value "BIOS update failed with exit code $($FlashExitCode)" -Severity 3
					$null = Enable-BitLockerProtection
					exit $FlashExitCode
				}
			}
		}
		catch [System.Exception]
		{
			Write-CMLogEntry -Value "An error occured while updating the system BIOS in OS online phase. Error message: $($_.Exception.Message)" -Severity 3
			$null = Enable-BitLockerProtection
			exit 1
		}
	}
}
