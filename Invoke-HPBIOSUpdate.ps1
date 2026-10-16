<#
.SYNOPSIS
    Invoke HP BIOS Update process.

.DESCRIPTION
    This script will invoke the HP BIOS update process using automatic detection of the flash utility with the update file specified for the Path parameter.

.PARAMETER Path
    Specify the %OSDBIOSPackage01% TS environment variable populated by the Invoke-CMDownloadBIOSPackage.ps1 script.

.PARAMETER PasswordBin
    Specify the BIOS password file if necessary (save the password file to the same directory as this script).

.EXAMPLE
    .\Invoke-HPBIOSUpdate.ps1 -Path %OSDBIOSPackage01% -PasswordBin "Password.bin"

.NOTES
    FileName:    Invoke-HPBIOSUpdate.ps1
    Author:      Lauri Kurvinen / Nickolaj Andersen
    Contact:     @estmi / @NickolajA
    Created:     2017-09-05
    Updated:     2020-04-23

    Version history:
	1.0.0 - (2017-09-05) Script created
	1.0.1 - (2018-01-30) Updated encrypted volume check and cleaned up some logging messages
	1.0.2 - (2018-06-14) Added support for HPFirmwareUpdRec utility - thanks to Jann Idar Hillestad (jihillestad@hotmail.com)
	1.0.3 - (2019-04-30) Updated to support HPQFlash.exe and HPQFlash64.exe
	1.0.4 - (2019-05-14) Handle $PasswordBin to check if empty string or null instead of just null value
	1.0.5 - (2019-05-14) Fixed an issue where the flash utility would look in the script executing location instead of the passed $Path location for the update file
	1.0.6 - (2020-02-06) Previous "fix" in 1.0.5 was a mistake, this version corrects it
	1.0.7 - (2020-04-23) Added additional logging output when flash utility is being executed including exit code. Removed the LogFileName parameter as the
			   	         exit code from the flash utility is now embedded in the Invoke-HPBIOSUpdate.log file.
#>

[CmdletBinding()]
param(
	[parameter(Mandatory = $true, HelpMessage = "Specify the path containing the HPBIOSUPDREC executable and bios update *.bin -file.")]
	[ValidateNotNullOrEmpty()]
	[string]$Path,

	[parameter(Mandatory = $false, HelpMessage = "Specify the BIOS password filename if necessary (save the password file to the same directory as the script).")]
	[ValidateNotNullOrEmpty()]
	[string]$PasswordBin
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
			[string]$FileName = "Invoke-HPBIOSUpdate.log"
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
		$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""HPBIOSUpdate.log"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

		# Add value to log file
		try {
			Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
		}

		catch [System.Exception] {
			Write-Warning -Message "Unable to append log entry to Invoke-HPBIOSUpdate.log file. Error message: $($_.Exception.Message)"
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

	# Change working directory to path containing BIOS files
	Set-Location -Path $Path
	Write-CMLogEntry -Value "Working directory set as $($Path)" -Severity 1

	# Write log file for script execution
	Write-CMLogEntry -Value "Initiating script to determine flashing capabilities for HP BIOS updates" -Severity 1

	# Attempt to detect HPBIOSUPDREC utility file name
	if (([Environment]::Is64BitOperatingSystem) -eq $true) {
		$HPBIOSUPDUtil = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "HPBIOSUPDREC64.exe" } | Select-Object -First 1 -ExpandProperty FullName
	}
	else {
		$HPBIOSUPDUtil = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "HPBIOSUPDREC.exe" } | Select-Object -First 1 -ExpandProperty FullName
	}

    # Attempt to detect HPFirmwareUpdRec utility file name
	if (([Environment]::Is64BitOperatingSystem) -eq $true) {
		$HPFirmwareUpdRec = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "HpFirmwareUpdRec64.exe" } | Select-Object -First 1 -ExpandProperty FullName
	}
	else {
		$HPFirmwareUpdRec = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "HpFirmwareUpdRec.exe" } | Select-Object -First 1 -ExpandProperty FullName
	}

    # Attempt to detect HPQFlash utility file name
	if (([Environment]::Is64BitOperatingSystem) -eq $true) {
		$HPFlashUtil = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "HPQFlash64.exe" } | Select-Object -First 1 -ExpandProperty FullName
	}
	else {
		$HPFlashUtil = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "HPQFlash.exe" } | Select-Object -First 1 -ExpandProperty FullName
	}

	# Select a single flash utility in order of preference. These blocks must remain mutually exclusive, otherwise a
	# package that ships more than one utility would silently overwrite the previously selected one.
	if ($HPBIOSUPDUtil -ne $null) {
		# Set required switches for silent upgrade of the bios and logging
		Write-CMLogEntry -Value "Using HPBIOSUpdRec BIOS update method" -Severity 1
		# This -r switch appears to be undocumented, which is a shame really, but this prevents the reboot without exit code. The command now returns a correct exit code and lets ConfigMgr reboot the computer gracefully.
		$FlashSwitches = " -s -r"
		$FlashUtility = $HPBIOSUPDUtil
	}
	elseif ($HPFirmwareUpdRec -ne $null) {
		# Set required switches for silent upgrade of the bios and logging
		Write-CMLogEntry -Value "Using HPFirmwareUpdRec BIOS update method" -Severity 1
		# This -r switch appears to be undocumented, which is a shame really, but this prevents the reboot without exit code. The command now returns a correct exit code and lets ConfigMgr reboot the computer gracefully.
		$FlashSwitches = " -s -r"
		$FlashUtility = $HPFirmwareUpdRec
	}
	elseif ($HPFlashUtil -ne $null) {
		# Set required switches for silent upgrade of the bios and logging
		Write-CMLogEntry -Value "Using HPQFlash BIOS update method" -Severity 1
		# This -r switch appears to be undocumented, which is a shame really, but this prevents the reboot without exit code. The command now returns a correct exit code and lets ConfigMgr reboot the computer gracefully.
		$FlashSwitches = " -s -r"
		$FlashUtility = $HPFlashUtil
	}

	if (-not($FlashUtility)) {
		Write-CMLogEntry -Value "Supported upgrade utility was not found." -Severity 3; exit 1
	}

	if (-not([System.String]::IsNullOrEmpty($PasswordBin))) {
		# Add password to the flash bios switches
		$FlashSwitches = $FlashSwitches + " -p""$($PSScriptRoot)\$($PasswordBin)"""
		Write-CMLogEntry -Value "Using the following switches for BIOS file: $($FlashSwitches)" -Severity 1
	}
	else {
		Write-CMLogEntry -Value "Using the following switches for BIOS file: $($FlashSwitches)" -Severity 1
	}

	# Determine if we're running in WinPE or Full OS
	if (($TSEnvironment -ne $null) -and ($TSEnvironment.Value("_SMSTSinWinPE") -eq $true)) {
		try {
			# Start flash update process
			Write-CMLogEntry -Value "Running Flash Update: $($FlashUtility)$($FlashSwitches)" -Severity 1
			$FlashProcess = Start-Process -FilePath $FlashUtility -ArgumentList $FlashSwitches -Passthru -Wait -ErrorAction Stop
			$FlashExitCode = $FlashProcess.ExitCode

			# Output Exit Code
			Write-CMLogEntry -Value "Flash utility exit code: $($FlashExitCode)" -Severity 1
		}
		catch [System.Exception] {
			Write-CMLogEntry -Value "An error occured while updating the system BIOS in WinPE phase. Error message: $($_.Exception.Message)" -Severity 3; exit 1
		}

		# Evaluate the exit code returned by the flash utility. Only 0 (success) and 3010 (success, reboot required)
		# are documented as successful, anything else has to fail the task sequence step.
		switch ($FlashExitCode) {
			0 {
				Write-CMLogEntry -Value "The BIOS update completed successfully." -Severity 1
			}
			3010 {
				Write-CMLogEntry -Value "The BIOS update completed successfully, a reboot is required to apply the new BIOS version." -Severity 1
				if ($TSEnvironment -ne $null) {
					$TSEnvironment.Value("SMSTSBIOSUpdateRebootRequired") = "True"
				}
			}
			default {
				Write-CMLogEntry -Value "The BIOS update failed. Flash utility returned exit code: $($FlashExitCode)" -Severity 3; exit $FlashExitCode
			}
		}
	}
	else {
		# Used in a later section of the task sequence
		# Detect Bitlocker Status
		try {
			$EncryptedVolumes = @(Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" -ErrorAction Stop | Where-Object { $_.DriveLetter -eq $env:SystemDrive })
		}
		catch [System.Exception] {
			Write-CMLogEntry -Value "An error occured while detecting the BitLocker protection status of volume: $($env:SystemDrive). Error message: $($_.Exception.Message)" -Severity 3; exit 1
		}
		if (($EncryptedVolumes.Count -ne 1) -or ($EncryptedVolumes[0].ProtectionStatus -notin @(0, 1))) {
			Write-CMLogEntry -Value "BitLocker inventory did not return one supported protection state for volume $($env:SystemDrive). BIOS update is blocked." -Severity 3; exit 1
		}
		$OSDriveEncrypted = $EncryptedVolumes[0].ProtectionStatus -eq 1

		# Suspend BitLocker if the operating system volume is protected
		if ($OSDriveEncrypted -eq $true) {
			Write-CMLogEntry -Value "Suspending BitLocker protected volume: $($env:SystemDrive)" -Severity 1
			Manage-Bde -Protectors -Disable $env:SystemDrive -RebootCount 1 | Out-Null
			if ($LASTEXITCODE -ne 0) {
				Write-CMLogEntry -Value "Failed to suspend BitLocker protection on volume $($env:SystemDrive). Manage-Bde returned exit code $($LASTEXITCODE)." -Severity 3; exit 1
			}
			$Script:BitLockerSuspendedByScript = $true

			# Verify that protection was actually suspended before flashing the BIOS
			try {
				$VerifyVolume = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" -ErrorAction Stop | Where-Object { $_.DriveLetter -eq $env:SystemDrive }
			}
			catch [System.Exception] {
				Write-CMLogEntry -Value "Unable to verify BitLocker suspension on volume $($env:SystemDrive). Error message: $($_.Exception.Message)" -Severity 3
				$null = Enable-BitLockerProtection
				exit 1
			}
			if (($VerifyVolume -eq $null) -or ($VerifyVolume.ProtectionStatus -ne 0)) {
				Write-CMLogEntry -Value "Failed to suspend BitLocker protection on volume: $($env:SystemDrive). Aborting BIOS update to prevent a recovery key prompt." -Severity 3
				$null = Enable-BitLockerProtection
				exit 1
			}
		}

		# Start Bios update process
		try {
			Write-CMLogEntry -Value "Running Flash Update: $($FlashUtility)$($FlashSwitches)" -Severity 1
			$FlashProcess = Start-Process -FilePath $FlashUtility -ArgumentList $FlashSwitches -Passthru -Wait -ErrorAction Stop
			$FlashExitCode = $FlashProcess.ExitCode

			# Output Exit Code
			Write-CMLogEntry -Value "Flash utility exit code: $($FlashExitCode)" -Severity 1
		}
		catch [System.Exception] {
			Write-CMLogEntry -Value "An error occured while updating the system BIOS in Full OS phase. Error message: $($_.Exception.Message)" -Severity 3
			$null = Enable-BitLockerProtection
			exit 1
		}

		# Evaluate the exit code returned by the flash utility. Only 0 (success) and 3010 (success, reboot required)
		# are documented as successful, anything else has to fail the task sequence step.
		switch ($FlashExitCode) {
			0 {
				Write-CMLogEntry -Value "The BIOS update completed successfully." -Severity 1
				if (-not (Enable-BitLockerProtection)) {
					exit 1
				}
			}
			3010 {
				Write-CMLogEntry -Value "The BIOS update completed successfully, a reboot is required to apply the new BIOS version." -Severity 1
				if ($TSEnvironment -ne $null) {
					$TSEnvironment.Value("SMSTSBIOSUpdateRebootRequired") = "True"
				}
			}
			default {
				Write-CMLogEntry -Value "The BIOS update failed. Flash utility returned exit code: $($FlashExitCode)" -Severity 3
				$null = Enable-BitLockerProtection
				exit $FlashExitCode
			}
		}
	}
}
