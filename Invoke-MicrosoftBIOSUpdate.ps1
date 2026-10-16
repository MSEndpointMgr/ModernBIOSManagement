<#
.SYNOPSIS
    Invoke Microsoft Update process.

.DESCRIPTION
    This script will invoke the Microsoft BIOS update process for the executable residing in the path specified for the Path parameter.

.PARAMETER LogFileName
    Set the name of the log file produced by the flash utility.

.EXAMPLE
    .\Invoke-MicrosoftBIOSUpdate.ps1 -LogFileName "LogFileName.log"

.NOTES
    FileName:    Invoke-MicrosoftBIOSUpdate.ps1
    Authors:     Maurice Daly / Nickolaj Andersen
    Contact:     @modaly_it / @NickolajA
    Created:     2019-07-11
    Updated:     2020-04-11

    Version history:
    1.0.0 - (2019-07-11) Script created (Maurice Daly)
	1.0.1 - (2019-07-25) Minor fixes
	1.0.2 - (2020-04-11) Removed unnecessary parameter Path, it was never used in the script
#>
[CmdletBinding()]
param(
    [parameter(Mandatory=$false, HelpMessage="Set the name of the log file produced by the flash utility.")]
    [ValidateNotNullOrEmpty()]
    [string]$LogFileName = "MicrosoftBIOSUpdate.log"
)
Begin {
	# Load Microsoft.SMS.TSEnvironment COM object
	try {
		$TSEnvironment = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop
	}
	catch [System.Exception] {
		Write-Warning -Message "Unable to construct Microsoft.SMS.TSEnvironment object. Error message: $($_.Exception.Message)"
		exit 1
	}
}
Process {
	# Set Log Path
	$LogsDirectory = Join-Path $env:SystemRoot "Temp"

    # Functions
    function Write-CMLogEntry {
	    param(
		    [parameter(Mandatory=$true, HelpMessage="Value added to the log file.")]
		    [ValidateNotNullOrEmpty()]
		    [string]$Value,

		    [parameter(Mandatory=$true, HelpMessage="Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		    [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
		    [string]$Severity,

		    [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
		    [ValidateNotNullOrEmpty()]
		    [string]$FileName = $Script:LogFileName
	    )
	    # Determine log file location, falling back to the local logs directory when not running inside a task sequence
        $LogDirectoryPath = if ($null -ne $TSEnvironment) { $TSEnvironment.Value("_SMSTSLogPath") } else { $null }
        if ([string]::IsNullOrEmpty($LogDirectoryPath)) {
            $LogDirectoryPath = $LogsDirectory
        }
        $LogFilePath = Join-Path -Path $LogDirectoryPath -ChildPath $FileName

        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-CimInstance -ClassName Win32_TimeZone | Select-Object -ExpandProperty Bias))

        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")

        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""MicrosoftBIOSUpdate.log"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

	    # Add value to log file
        try {
	        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to Invoke-MicrosoftBIOSUpdate.log file. Error message: $($_.Exception.Message)"
        }
    }

	function Invoke-Executable {
		param (
			[parameter(Mandatory = $true, HelpMessage = "Specify the file name or path of the executable to be invoked, including the extension")]
			[ValidateNotNullOrEmpty()]
			[string]$FilePath,
			[parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the executable")]
			[ValidateNotNull()]
			[string]$Arguments
		)

		# Construct a hash-table for default parameter splatting
		$SplatArgs = @{
			FilePath = $FilePath
			NoNewWindow = $true
			Passthru = $true
			ErrorAction = "Stop"
		}

		# Add ArgumentList param if present
		if (-not ([System.String]::IsNullOrEmpty($Arguments))) {
			$SplatArgs.Add("ArgumentList", $Arguments)
		}

		# Invoke executable and wait for process to exit
		try {
			$Invocation = Start-Process @SplatArgs
			# Caching the process handle ensures the ExitCode property is populated once the process ends
			$null = $Invocation.Handle
			$Invocation.WaitForExit()
		}
		catch [System.Exception] {
			Write-CMLogEntry -Value "Failed to invoke '$($FilePath)'. Error message: $($_.Exception.Message)" -Severity 3
			return 1
		}

		return $Invocation.ExitCode
	}

	# A virtual machine has no physical firmware flash chip. The guest BIOS/UEFI is a software template
	# owned by the hypervisor, so firmware payloads cannot be applied inside the guest. Skip gracefully.
	try {
		$ComputerSystems = @(Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop)
	}
	catch [System.Exception] {
		Write-CMLogEntry -Value "Unable to inventory the computer platform safely. Firmware update is blocked. Error message: $($_.Exception.Message)" -Severity 3
		exit 1
	}
	if (($ComputerSystems.Count -ne 1) -or [string]::IsNullOrWhiteSpace([string]$ComputerSystems[0].Model) -or [string]::IsNullOrWhiteSpace([string]$ComputerSystems[0].Manufacturer)) {
		Write-CMLogEntry -Value "Computer platform inventory did not return one complete system identity. Firmware update is blocked." -Severity 3
		exit 1
	}
	$ComputerSystem = $ComputerSystems[0]
	$VirtualMachineModels = @("Virtual Machine", "VMware Virtual Platform", "VMware7,1", "VMware20,1", "VMware Virtual Platform None", "VirtualBox", "HVM domU", "KVM", "QEMU Virtual Machine", "Standard PC (Q35 + ICH9, 2009)", "Standard PC (i440FX + PIIX, 1996)", "Parallels Virtual Platform", "Google Compute Engine", "AHV")
	if (($ComputerSystem.Model -in $VirtualMachineModels) -or ($ComputerSystem.Manufacturer -match "VMware|QEMU|innotek|Xen|Parallels|Nutanix|Red Hat|Google|Amazon EC2|OpenStack")) {
		Write-CMLogEntry -Value "Virtual machine detected ('$($ComputerSystem.Manufacturer) $($ComputerSystem.Model)'). BIOS/UEFI firmware is managed by the hypervisor, skipping BIOS flash" -Severity 2
		exit 0
	}

	# Default to task sequence variable set in detection script
	if (($null -ne $TSEnvironment) -and (-not([string]::IsNullOrEmpty($TSEnvironment.Value("OSDBIOSPackage01"))))) {
		Write-CMLogEntry -Value "Using BIOS package location set in OSDBIOSPackage01 TS variable" -Severity 1
		$OSDFirmwarePackageLocation = $TSEnvironment.Value("OSDBIOSPackage01")
	}

	# Run BIOS update process if BIOS package exists
	if (-not([string]::IsNullOrEmpty($OSDFirmwarePackageLocation))){
		# Write log file for script execution
		Write-CMLogEntry -Value "Initiating pnputil to apply firmware updates" -Severity 1

		$FirmwareInfPath = Join-Path -Path $OSDFirmwarePackageLocation -ChildPath "*.inf"
		$FirmwareLogPath = Join-Path -Path $LogsDirectory -ChildPath "Install-MicrosoftFirmware.txt"

		# Paths are quoted to support spaces and the native exit code is propagated back to the caller
		$PnPUtilCommand = "pnputil.exe /add-driver '$($FirmwareInfPath)' /subdirs /install | Out-File -FilePath '$($FirmwareLogPath)' -Force; exit `$LASTEXITCODE"
		$ApplyFirmwareInvocation = Invoke-Executable -FilePath "powershell.exe" -Arguments "-ExecutionPolicy Bypass -NoProfile -Command ""& { $($PnPUtilCommand) }"""

		switch ($ApplyFirmwareInvocation) {
			0 {
				Write-CMLogEntry -Value "Firmware update staging completed successfully" -Severity 1
			}
			3010 {
				Write-CMLogEntry -Value "Firmware update staging completed successfully, a reboot is required to apply the firmware" -Severity 1
				if ($TSEnvironment -ne $null) {
					$TSEnvironment.Value("SMSTSBIOSUpdateRebootRequired") = "True"
				}
			}
			default {
				Write-CMLogEntry -Value "Firmware update staging failed with exit code: $($ApplyFirmwareInvocation)" -Severity 3
				exit $ApplyFirmwareInvocation
			}
		}
	}
	else {
		Write-CMLogEntry -Value "Unable to determine BIOS package path." -Severity 3 ; exit 1
	}
}
