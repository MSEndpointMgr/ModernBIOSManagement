<#
.SYNOPSIS
	Download BIOS package (regular package) matching computer model and manufacturer.

.DESCRIPTION
    This script will determine the model of the computer and manufacturer and then query the specified endpoint
    for ConfigMgr WebService for a list of Packages. It then sets the OSDDownloadDownloadPackages variable to include
    the PackageID property of a package matching the computer model. If multiple packages are detect, it will select
	most current one by the creation date of the packages.

.PARAMETER BareMetal
	Set the script to operate in 'BareMetal' (WinPE) deployment type mode.

.PARAMETER BIOSUpdate
	Set the script to operate in 'BIOSUpdate' (full OS) deployment type mode.

.PARAMETER XMLPackage
	Set the script to operate in 'XMLPackage' deployment type mode, where BIOS package details are read from a pre-downloaded DriverPackages.xml logic file instead of the AdminService.

.PARAMETER XMLDeploymentType
	Specify the deployment type mode for XML based BIOS package deployments, e.g. 'BareMetal' or 'BIOSUpdate'.

.PARAMETER DebugMode
	Set the script to operate in 'DebugMode' deployment type mode.

.PARAMETER Endpoint
	Specify the internal fully qualified domain name of the server hosting the AdminService, e.g. CM01.domain.local.

.PARAMETER UserName
	Specify the service account user name used for authenticating against the AdminService endpoint.

.PARAMETER Password
	Specify the service account password used for authenticating against the AdminService endpoint.

.PARAMETER Filter
	Define a filter used when calling ConfigMgr WebService to only return objects matching the filter.

.PARAMETER OperationalMode
	Define the operational mode, either Production or Pilot, for when calling ConfigMgr WebService to only return objects matching the selected operational mode.

.PARAMETER Manufacturer
	Override the automatically detected computer manufacturer when running in debug mode.

.PARAMETER ComputerModel
	Override the automatically detected computer model when running in debug mode.

.PARAMETER SystemSKU
	Override the automatically detected SystemSKU when running in debug mode.

.PARAMETER ForceDownload
	Force the matching BIOS package to be downloaded (and flagged for flashing) even when the installed BIOS version already matches the package version. This is an opt-in switch used for intentional re-application scenarios -- for example recreating Dell BIOS recovery images on newer Pro/Precision platforms after OS deployment, SSD replacement or disk wipes. The equivalent task sequence variable is SMSTSForceBIOSDownload=True. Default behaviour (skip when already up to date) is unchanged.

.EXAMPLE
	# Detect and download latest available BIOS package with ConfigMgr through the admin service in a baremetal deployment (default):
	.\Invoke-CMDownloadBIOSPackage.ps1 -BareMetal -Endpoint "CM01.domain.com"

	# Detect and download latest available BIOS package with ConfigMgr through the admin service in a full OS deployment:
	.\Invoke-CMDownloadBIOSPackage.ps1 -BIOSUpdate -Endpoint "CM01.domain.com"

	# Detect and download latest available BIOS package using a pre-downloaded XML package logic file in a baremetal deployment:
	.\Invoke-CMDownloadBIOSPackage.ps1 -XMLPackage -XMLDeploymentType "BareMetal"

	# Detect and download latest available BIOS package using a pre-downloaded XML package logic file in a full OS deployment:
	.\Invoke-CMDownloadBIOSPackage.ps1 -XMLPackage -XMLDeploymentType "BIOSUpdate"

	# Detect, and report on the matched BIOS release without downloading / in full OS
	.\Invoke-CMDownloadBIOSPackage.ps1 -Endpoint "CM01.domain.com" -UserName "Username" -Password "Password" -DebugMode

	# Detect, and report on the matched BIOS release without downloading / in full OS, with the make / model / sku specified
	.\Invoke-CMDownloadBIOSPackage.ps1 -Endpoint "CM01.domain.com" -UserName "Username" -Password "Password" -Manufacturer "HP" -ComptuerModel "ZBook Studio x360 G5" -SystemSKU "8427" -DebugMode

.NOTES
    FileName:    Invoke-CMDownloadBIOSPackage.ps1
	Author:      Nickolaj Andersen / Maurice Daly
    Contact:     @NickolajA / @MoDaly_IT
    Created:     2020-10-30
    Updated:     2026-10-01

    Version history:
    3.0.0 - (2020-10-30) - Script created
	3.0.1 - (2020-12-04) - Fixes to parameter sets, matching logic and removal of no longer code
						 - Added TS variable support for Resource URL
	3.0.2 - (2020-12-09) - Added new functionality to be able to read a custom Application ID URI, if the default of https://ConfigMgrService is not defined on the ServerApp.
	3.0.3 - (2020-12-10) - Fixed issue in WinPE, with addition of baremetal parameter switch (now default)
						   Added BIOSUpdate parameter switch for Full OS deployments
	3.0.4 - (2026-08-05) - Multiple-package selection hardening and fixes:
						 - Fixed Lenovo model-name fallback that re-sorted an already-nulled package list, causing valid model-type matches to be discarded and the run to bail out (exit 1).
						 - Unified the "latest package" sort key to SourceDate for HP and Microsoft (previously PackageCreated, which is not a property on the AdminService SMS_Package object, so the list was left unsorted and an older package could be selected).
						 - Tightened SystemSKU matching to compare whole alphanumeric tokens instead of using -match (regex substring), preventing spurious multi-package matches where a short SKU matched inside another SKU or elsewhere in the description.
						 - Normalised the reduced package list to an array so .Count and index access behave predictably after Select-Object -First 1.
						 - Corrected $null comparisons to place $null on the left-hand side.
						 - Added a documented placeholder (default) branch in Get-ComputerData describing how to add support for custom/unlisted manufacturers.
						 - Logging improvements for troubleshooting: Invoke-Executable launch failures are now written to the log file (Severity 3) instead of only Write-Warning, and return -1 rather than silently continuing; Get-ComputerData wraps manufacturer detection in try/catch that logs the manufacturer context on failure and degrades gracefully; and a script version + key parameter banner is written at startup.
	3.0.5 - (2026-08-21) - Fixed BIOS package detection failing in a live task sequence while succeeding in DebugMode (#902):
					 - Get-BIOSUpdate matched packages against the script-level $ComputerModel parameter, which is only populated in DebugMode. In a real (BareMetal/BIOSUpdate) run it was empty, so the ComputerModel detection method and the SystemSKU-to-model fallback compared against a blank string and never matched -- most visible on Lenovo, where the SystemSKU is only the 4-char machine type and the model-name fallback is often required. Now uses $ComputerSystemType (the detected/overridden $InputObject.Model) so matching behaves identically in both modes.
	3.0.6 - (2026-08-31) - Added optional force-download support for intentional BIOS re-application (MSEndpointMgr/ModernBIOSManagement#31):
					 - New -ForceDownload switch (and SMSTSForceBIOSDownload=True task sequence variable) downloads the matching BIOS package and flags it for flashing (NewBIOSAvailable=true) even when the installed version already matches the package version. Enables recreating Dell BIOS recovery images (stored on internal NVMe) after OSD, SSD replacement or disk wipes. Opt-in only; default behaviour (skip when already up to date) is unchanged. Note: forcing the flash of the same version on Dell also requires the companion Dell BIOS update step to pass Dell's /f switch.
	3.0.7 - (2026-09-03) - Added the missing XMLPackage parameter set (MSEndpointMgr/ModernBIOSManagement#32):
					 - The script body already implemented XML (non-AdminService) package logic -- Get-DeploymentType, Get-BIOSPackages and the AdminService phase all branch on the 'XMLPackage' parameter set name -- but the parameter set itself was never declared in the param block. Running the script with -XMLPackage therefore failed at parameter binding ("A parameter cannot be found that matches parameter name 'XMLPackage'"), making XML/standalone (webservice-less) BIOS deployments impossible. Added the -XMLPackage switch and -XMLDeploymentType parameter (BareMetal/BIOSUpdate), and extended -Filter, -OperationalMode and -ForceDownload to the XMLPackage parameter set.
					 - Fixed the "latest package by creation date" selection sorting SourceDate as text rather than as a date. Packages read from the XML logic file always carry SourceDate as a string, so Sort-Object compared text and, with a culture formatted stamp ('03/09/2026 12:00:00'), an older BIOS package could be selected whenever multiple packages matched a device. New ConvertTo-PackageSourceDate helper normalises ISO 8601, WMI DMTF, culture formatted and DateTime values to a sortable [datetime] (unparsable values sort last), and all five Dell/Lenovo/HP/Microsoft selection sorts now use it.
	3.0.8 - (2026-09-03) - Added AdminService authentication resiliency for environments that reject a bare service account user name:
					 - Some environments return 401 Unauthorized when AdminService authentication uses a bare account name (e.g. 'svc-osd'). Microsoft does not document this as a ConfigMgr 2603 UPN-only requirement. Get-AuthCredential now identifies a non-UPN value and names the domain-qualified alternatives that will be attempted.
					 - Get-AuthDomainName resolves the Active Directory DNS domain from, in order: the OSDDOMAINNAME / OSDJoinDomainName task sequence variables, the domain membership of the running device (full OS only), and the DNS suffix of the AdminService endpoint or management point host name (the only sources available in WinPE).
					 - Get-AdminServiceItem now retries the request with the UPN form (user@domain.com) and then the down-level form (DOMAIN\user) when, and only when, the AdminService responds with 401 Unauthorized. The configured value is always attempted first so a working environment is unchanged, the working credential is reused for the remainder of the run, and a run where every format is rejected logs explicit guidance to move the account to UPN format.
					 - Certificate validation failures are surfaced as errors. AdminService must present a certificate trusted by the task-sequence environment; the script never installs a process-wide certificate-validation bypass.
	3.0.9 - (2026-10-01) - Hardened AdminService and firmware-update safety:
					 - Removed certificate-validation bypasses from both downloaders. HTTPS endpoints must now use certificates trusted by the client or WinPE trust store.
					 - Vendor flash scripts now fail closed when hardware inventory or BitLocker status cannot be read, use a one-reboot BitLocker suspension, and restore protection immediately when no reboot is pending or the flash fails.
					 - Added non-task-sequence log-path fallbacks and escaped BIOS passwords before masking command-line logs.

#>
[CmdletBinding(DefaultParameterSetName = "BareMetal")]
param (
	[parameter(Mandatory = $true, ParameterSetName = "BareMetal", HelpMessage = "Set the script to operate in 'BareMetal' deployment type mode.")]
	[switch]$BareMetal,

	[parameter(Mandatory = $true, ParameterSetName = "BIOSUpdate", HelpMessage = "Set the script to operate in 'BIOSUpdate' deployment type mode.")]
	[switch]$BIOSUpdate,

	[parameter(Mandatory = $true, ParameterSetName = "XMLPackage", HelpMessage = "Set the script to operate in 'XMLPackage' deployment type mode.")]
	[switch]$XMLPackage,

	[parameter(Mandatory = $true, ParameterSetName = "BIOSUpdate", HelpMessage = "Specify the internal fully qualified domain name of the server hosting the AdminService, e.g. CM01.domain.local.")]
	[parameter(Mandatory = $true, ParameterSetName = "BareMetal")]
	[parameter(Mandatory = $true, ParameterSetName = "Debug")]
	[ValidateNotNullOrEmpty()]
	[string]$Endpoint,

	[parameter(Mandatory = $false, ParameterSetName = "XMLPackage", HelpMessage = "Specify the deployment type mode for XML based BIOS package deployments, e.g. 'BareMetal' or 'BIOSUpdate'.")]
	[ValidateNotNullOrEmpty()]
	[ValidateSet("BareMetal", "BIOSUpdate")]
	[string]$XMLDeploymentType = "BareMetal",

	[parameter(Mandatory = $false, ParameterSetName = "Debug", HelpMessage = "Set the script to operate in 'DebugMode' deployment type mode.")]
	[switch]$DebugMode,

	[parameter(Mandatory = $true, ParameterSetName = "Debug", HelpMessage = "Specify the service account user name used for authenticating against the AdminService endpoint.")]
	[ValidateNotNullOrEmpty()]
	[string]$UserName = "",

	[parameter(Mandatory = $true, ParameterSetName = "Debug", HelpMessage = "Specify the service account password used for authenticating against the AdminService endpoint.")]
	[ValidateNotNullOrEmpty()]
	[string]$Password = "",

	[parameter(Mandatory = $false, ParameterSetName = "BIOSUpdate", HelpMessage = "Define a filter used when calling the AdminService to only return objects matching the filter.")]
	[parameter(Mandatory = $false, ParameterSetName = "BareMetal")]
	[parameter(Mandatory = $false, ParameterSetName = "XMLPackage")]
	[ValidateNotNullOrEmpty()]
	[string]$Filter = "BIOS",

	[parameter(Mandatory = $false, ParameterSetName = "BIOSUpdate", HelpMessage = "Define the operational mode, either Production or Pilot, for when calling ConfigMgr WebService to only return objects matching the selected operational mode.")]
	[parameter(Mandatory = $false, ParameterSetName = "BareMetal")]
	[parameter(Mandatory = $true, ParameterSetName = "Debug")]
	[parameter(Mandatory = $false, ParameterSetName = "XMLPackage")]
	[ValidateNotNullOrEmpty()]
	[ValidateSet("Production", "Pilot")]
	[string]$OperationalMode = "Production",

	[parameter(Mandatory = $false, ParameterSetName = "Debug", HelpMessage = "Override the automatically detected computer manufacturer when running in debug mode.")]
	[ValidateNotNullOrEmpty()]
	[ValidateSet("Hewlett-Packard", "HP", "Dell", "Lenovo", "Microsoft", "Fujitsu", "Panasonic", "Viglen", "AZW")]
	[string]$Manufacturer,

	[parameter(Mandatory = $false, ParameterSetName = "Debug", HelpMessage = "Override the automatically detected computer model when running in debug mode.")]
	[ValidateNotNullOrEmpty()]
	[string]$ComputerModel,

	[parameter(Mandatory = $false, ParameterSetName = "Debug", HelpMessage = "Override the automatically detected SystemSKU when running in debug mode.")]
	[ValidateNotNullOrEmpty()]
	[string]$SystemSKU,

	[parameter(Mandatory = $false, ParameterSetName = "BareMetal", HelpMessage = "Force the BIOS package to download and flag for flashing even when the installed version already matches (opt-in; for intentional re-application such as Dell recovery image recreation).")]
	[parameter(Mandatory = $false, ParameterSetName = "BIOSUpdate")]
	[parameter(Mandatory = $false, ParameterSetName = "Debug")]
	[parameter(Mandatory = $false, ParameterSetName = "XMLPackage")]
	[switch]$ForceDownload
)
Begin {

	# Load Microsoft.SMS.TSEnvironment COM object
	if ($PSCmdLet.ParameterSetName -notlike "Debug") {
		try {
			$TSEnvironment = New-Object -ComObject "Microsoft.SMS.TSEnvironment" -ErrorAction Stop
		} catch [System.Exception] {
			throw "Unable to construct Microsoft.SMS.TSEnvironment object. $($PSItem.Exception.Message)"
		}
	}

	# Set Security Protocol (TLS)
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Process {
	# Set Log Path
	switch ($PSCmdLet.ParameterSetName) {
		"Debug" {
			$LogsDirectory = Join-Path -Path $env:SystemRoot -ChildPath "Temp"
		}
		default {
			$LogsDirectory = $Script:TSEnvironment.Value("_SMSTSLogPath")
		}
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
			[string]$FileName = "ApplyBIOSPackage.log"
		)
		# Determine log file location
		$LogFilePath = Join-Path -Path $LogsDirectory -ChildPath $FileName

		# Construct time stamp for log entry
		if (-not (Test-Path -Path 'variable:global:TimezoneBias')) {
			[string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
			if ($TimezoneBias -match "^-") {
				$TimezoneBias = $TimezoneBias.Replace('-', '+')
			} else {
				$TimezoneBias = '-' + $TimezoneBias
			}
		}
		$Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)

		# Construct date for log entry
		$Date = (Get-Date -Format "MM-dd-yyyy")

		# Construct context for log entry
		$Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

		# Construct final log entry
		$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""ApplyBIOSPackage"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

		# Add value to log file
		try {
			Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
		} catch [System.Exception] {
			Write-Warning -Message "Unable to append log entry to ApplyBIOSPackage.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
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
			# Access .Handle to force the process object to cache the handle so WaitForExit()/ExitCode
			# work reliably; the value itself is intentionally discarded.
			$null = $Invocation.Handle
			$Invocation.WaitForExit()
		} catch [System.Exception] {
			# Log to the CMTrace log file -- Write-Warning alone is not captured in a task sequence,
			# so a failure to even launch the executable would otherwise leave no trace in the log.
			Write-CMLogEntry -Value " - Failed to invoke executable '$($FilePath)'. Error message: $($_.Exception.Message)" -Severity 3
			return -1
		}

		return $Invocation.ExitCode
	}

	function Invoke-CMDownloadContent {
		param (
			[parameter(Mandatory = $true, ParameterSetName = "NoPath", HelpMessage = "Specify a PackageID that will be downloaded.")]
			[Parameter(ParameterSetName = "CustomPath")]
			[ValidateNotNullOrEmpty()]
			[ValidatePattern("^[A-Z0-9]{3}[A-F0-9]{5}$")]
			[string]$PackageID,

			[parameter(Mandatory = $true, ParameterSetName = "NoPath", HelpMessage = "Specify the download location type.")]
			[Parameter(ParameterSetName = "CustomPath")]
			[ValidateNotNullOrEmpty()]
			[ValidateSet("Custom", "TSCache", "CCMCache")]
			[string]$DestinationLocationType,

			[parameter(Mandatory = $true, ParameterSetName = "NoPath", HelpMessage = "Save the download location to the specified variable name.")]
			[Parameter(ParameterSetName = "CustomPath")]
			[ValidateNotNullOrEmpty()]
			[string]$DestinationVariableName,

			[parameter(Mandatory = $true, ParameterSetName = "CustomPath", HelpMessage = "When location type is specified as Custom, specify the custom path.")]
			[ValidateNotNullOrEmpty()]
			[string]$CustomLocationPath
		)
		# Set OSDDownloadDownloadPackages
		Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDownloadPackages to: $($PackageID)" -Severity 1
		$TSEnvironment.Value("OSDDownloadDownloadPackages") = "$($PackageID)"

		# Set OSDDownloadDestinationLocationType
		Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationLocationType to: $($DestinationLocationType)" -Severity 1
		$TSEnvironment.Value("OSDDownloadDestinationLocationType") = "$($DestinationLocationType)"

		# Set OSDDownloadDestinationVariable
		Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationVariable to: $($DestinationVariableName)" -Severity 1
		$TSEnvironment.Value("OSDDownloadDestinationVariable") = "$($DestinationVariableName)"

		# Set OSDDownloadDestinationPath
		if ($DestinationLocationType -like "Custom") {
			Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationPath to: $($CustomLocationPath)" -Severity 1
			$TSEnvironment.Value("OSDDownloadDestinationPath") = "$($CustomLocationPath)"
		}

		# Set SMSTSDownloadRetryCount to 1000 to overcome potential BranchCache issue that will cause 'SendWinHttpRequest failed. 80072efe'
		$TSEnvironment.Value("SMSTSDownloadRetryCount") = 1000

		# Invoke download of package content
		try {
			if ($TSEnvironment.Value("_SMSTSInWinPE") -eq $false) {
				Write-CMLogEntry -Value " - Starting package content download process (FullOS), this might take some time" -Severity 1
				$ReturnCode = Invoke-Executable -FilePath (Join-Path -Path $env:windir -ChildPath "CCM\OSDDownloadContent.exe")
			} else {
				Write-CMLogEntry -Value " - Starting package content download process (WinPE), this might take some time" -Severity 1
				$ReturnCode = Invoke-Executable -FilePath "OSDDownloadContent.exe"
			}

			# Reset SMSTSDownloadRetryCount to 5 after attempted download
			$TSEnvironment.Value("SMSTSDownloadRetryCount") = 5

			# Match on return code
			if ($ReturnCode -eq 0) {
				Write-CMLogEntry -Value " - Successfully downloaded package content with PackageID: $($PackageID)" -Severity 1
			} else {
				Write-CMLogEntry -Value " - Failed to download package content with PackageID '$($PackageID)'. Return code was: $($ReturnCode)" -Severity 3

				# Throw terminating error
				$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
		} catch [System.Exception] {
			Write-CMLogEntry -Value " - An error occurred while attempting to download package content. Error message: $($_.Exception.Message)" -Severity 3

			# Throw terminating error
			$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}

		return $ReturnCode
	}

	function Invoke-CMResetDownloadContentVariables {
		# Set OSDDownloadDownloadPackages
		Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDownloadPackages to a blank value" -Severity 1
		$TSEnvironment.Value("OSDDownloadDownloadPackages") = [System.String]::Empty

		# Set OSDDownloadDestinationLocationType
		Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationLocationType to a blank value" -Severity 1
		$TSEnvironment.Value("OSDDownloadDestinationLocationType") = [System.String]::Empty

		# Set OSDDownloadDestinationVariable
		Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationVariable to a blank value" -Severity 1
		$TSEnvironment.Value("OSDDownloadDestinationVariable") = [System.String]::Empty

		# Set OSDDownloadDestinationPath
		Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationPath to a blank value" -Severity 1
		$TSEnvironment.Value("OSDDownloadDestinationPath") = [System.String]::Empty
	}

	function New-TerminatingErrorRecord {
		param (
			[parameter(Mandatory = $false, HelpMessage = "Specify the exception message details.")]
			[AllowEmptyString()]
			[string]$Message = ([string]::Empty),

			[parameter(Mandatory = $false, HelpMessage = "Specify the violation exception causing the error.")]
			[ValidateNotNullOrEmpty()]
			[string]$Exception = "System.Management.Automation.RuntimeException",

			[parameter(Mandatory = $false, HelpMessage = "Specify the unique identifier for the error record.")]
			[ValidateNotNullOrEmpty()]
			[string]$ErrorID = "ModernBIOSManagementError",

			[parameter(Mandatory = $false, HelpMessage = "Specify the error category of the exception causing the error.")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.ErrorCategory]$ErrorCategory = [System.Management.Automation.ErrorCategory]::NotImplemented,

			[parameter(Mandatory = $false, HelpMessage = "Specify the target object causing the error.")]
			[AllowEmptyString()]
			[string]$TargetObject = ([string]::Empty)
		)
		# Fall back to a generic message when no details were supplied, since an empty exception message hides the failure reason
		if ([string]::IsNullOrEmpty($Message)) {
			$Message = "An unrecoverable error occurred, review the log file for the preceding error entry for further details"
		}

		# Construct new error record to be returned from function based on parameter inputs
		$SystemException = New-Object -TypeName $Exception -ArgumentList $Message
		$ErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList @($SystemException, $ErrorID, $ErrorCategory, $TargetObject)

		# Handle return value
		return $ErrorRecord
	}

	function ConvertTo-PackageSourceDate {
		<#
		.SYNOPSIS
			Normalise a package SourceDate value into a sortable [datetime].

		.DESCRIPTION
			BIOS package selection sorts on SourceDate to pick the most recently created package.
			From the AdminService the value arrives as an ISO 8601 string or a DateTime, but from the
			XML package logic file it is always a string -- so an unconverted Sort-Object compares text
			rather than time. With a culture formatted stamp such as '03/09/2026 12:00:00' that ordering
			is simply wrong ('12/01/2026' sorts above '03/09/2026'), and an older BIOS package can win
			the selection. Handles ISO 8601, WMI DMTF datetime, culture formatted strings and DateTime
			input, and returns [datetime]::MinValue for missing or unparsable values so those packages
			sort last (oldest) instead of winning by accident.
		#>
		param (
			[parameter(Mandatory = $false, HelpMessage = "The SourceDate value to normalise.")]
			$Value
		)
		if ($null -eq $Value) { return [datetime]::MinValue }
		if ($Value -is [datetime]) { return $Value }

		$DateString = ([string]$Value).Trim()
		if ([string]::IsNullOrEmpty($DateString)) { return [datetime]::MinValue }

		# WMI DMTF datetime, e.g. 20260801120000.000000+000
		if ($DateString -match '^\d{14}\.') {
			try { return [System.Management.ManagementDateTimeConverter]::ToDateTime($DateString) } catch { }
		}

		# Current culture first: logic files written by earlier versions of the Driver Automation Tool
		# carry a culture formatted stamp, and only the local culture reads day/month order correctly.
		# ISO 8601 (written by current versions) parses identically under either culture, so the
		# invariant fallback only ever catches formats the local culture cannot read.
		$ParsedDate = [datetime]::MinValue
		if ([datetime]::TryParse($DateString, [System.Globalization.CultureInfo]::CurrentCulture, [System.Globalization.DateTimeStyles]::None, [ref]$ParsedDate)) { return $ParsedDate }
		if ([datetime]::TryParse($DateString, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$ParsedDate)) { return $ParsedDate }

		return [datetime]::MinValue
	}

	function Get-DeploymentType {
		switch ($PSCmdlet.ParameterSetName) {
			"XMLPackage" {
				# Set required variables for XMLPackage parameter set
				$Script:DeploymentMode = $Script:XMLDeploymentType
				$Script:PackageSource = "XML Package Logic file"

				# Define the path for the pre-downloaded XML Package Logic file called DriverPackages.xml
				$script:XMLPackageLogicFile = (Join-Path -Path $TSEnvironment.Value("MDMXMLPackage01") -ChildPath "DriverPackages.xml")
				if (-not (Test-Path -Path $XMLPackageLogicFile)) {
					Write-CMLogEntry -Value " - Failed to locate required 'DriverPackages.xml' logic file for XMLPackage deployment type, ensure it has been pre-downloaded in a Download Package Content step before running this script" -Severity 3

					# Throw terminating error
					$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
					$PSCmdlet.ThrowTerminatingError($ErrorRecord)
				}
			}
			default {
				$Script:DeploymentMode = $Script:PSCmdlet.ParameterSetName
				$Script:PackageSource = "AdminService"
			}
		}
	}

	function ConvertTo-ObfuscatedUserName {
		param (
			[parameter(Mandatory = $true, HelpMessage = "Specify the user name string to be obfuscated for log output.")]
			[ValidateNotNullOrEmpty()]
			[string]$InputObject
		)
		# Convert input object to a character array
		$UserNameArray = $InputObject.ToCharArray()

		# Loop through each character obfuscate every second item, with exceptions of the @ character if present
		for ($i = 0; $i -lt $UserNameArray.Count; $i++) {
			if ($UserNameArray[$i] -notmatch "@") {
				if ($i % 2) {
					$UserNameArray[$i] = "*"
				}
			}
		}

		# Join character array and return value
		return -join @($UserNameArray)
	}

	function Test-AdminServiceData {
		# Validate correct value have been either set as a TS environment variable or passed as parameter input for service account user name used to authenticate against the AdminService
		if ([string]::IsNullOrEmpty($Script:UserName)) {
			switch ($PSCmdLet.ParameterSetName) {
				"Debug" {
					Write-CMLogEntry -Value " - Required service account user name could not be determined from parameter input" -Severity 3

					# Throw terminating error
					$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
					$PSCmdlet.ThrowTerminatingError($ErrorRecord)
				}
				default {
					# Attempt to read TSEnvironment variable MDMUserName
					$Script:UserName = $TSEnvironment.Value("MDMUserName")
					if (-not ([string]::IsNullOrEmpty($Script:UserName))) {
						# Obfuscate user name
						$ObfuscatedUserName = ConvertTo-ObfuscatedUserName -InputObject $Script:UserName

						Write-CMLogEntry -Value " - Successfully read service account user name from TS environment variable 'MDMUserName': $($ObfuscatedUserName)" -Severity 1
					} else {
						Write-CMLogEntry -Value " - Required service account user name could not be determined from TS environment variable" -Severity 3

						# Throw terminating error
						$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
						$PSCmdlet.ThrowTerminatingError($ErrorRecord)
					}
				}
			}
		} else {
			# Obfuscate user name
			$ObfuscatedUserName = ConvertTo-ObfuscatedUserName -InputObject $Script:UserName

			Write-CMLogEntry -Value " - Successfully read service account user name from parameter input: $($ObfuscatedUserName)" -Severity 1
		}

		# Validate correct value have been either set as a TS environment variable or passed as parameter input for service account password used to authenticate against the AdminService
		if ([string]::IsNullOrEmpty($Script:Password)) {
			switch ($Script:PSCmdLet.ParameterSetName) {
				"Debug" {
					Write-CMLogEntry -Value " - Required service account password could not be determined from parameter input" -Severity 3
				}
				default {
					# Attempt to read TSEnvironment variable MDMPassword
					$Script:Password = $TSEnvironment.Value("MDMPassword")
					if (-not ([string]::IsNullOrEmpty($Script:Password))) {
						Write-CMLogEntry -Value " - Successfully read service account password from TS environment variable 'MDMPassword': ********" -Severity 1
					} else {
						Write-CMLogEntry -Value " - Required service account password could not be determined from TS environment variable" -Severity 3

						# Throw terminating error
						$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
						$PSCmdlet.ThrowTerminatingError($ErrorRecord)
					}
				}
			}
		} else {
			Write-CMLogEntry -Value " - Successfully read service account password from parameter input: ********" -Severity 1
		}

		# Validate that if determined AdminService endpoint type is external, that additional required TS environment variables are available
		if ($Script:AdminServiceEndpointType -like "External") {
			if ($Script:PSCmdLet.ParameterSetName -notlike "Debug") {
				# Attempt to read TSEnvironment variable MDMExternalEndpoint
				$Script:ExternalEndpoint = $TSEnvironment.Value("MDMExternalEndpoint")
				if (-not ([string]::IsNullOrEmpty($Script:ExternalEndpoint))) {
					Write-CMLogEntry -Value " - Successfully read external endpoint address for AdminService through CMG from TS environment variable 'MDMExternalEndpoint': $($Script:ExternalEndpoint)" -Severity 1
				} else {
					Write-CMLogEntry -Value " - Required external endpoint address for AdminService through CMG could not be determined from TS environment variable" -Severity 3

					# Throw terminating error
					$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
					$PSCmdlet.ThrowTerminatingError($ErrorRecord)
				}

				# Attempt to read TSEnvironment variable MDMClientID
				$Script:ClientID = $TSEnvironment.Value("MDMClientID")
				if (-not ([string]::IsNullOrEmpty($Script:ClientID))) {
					Write-CMLogEntry -Value " - Successfully read client identification for AdminService through CMG from TS environment variable 'MDMClientID': $($Script:ClientID)" -Severity 1
				} else {
					Write-CMLogEntry -Value " - Required client identification for AdminService through CMG could not be determined from TS environment variable" -Severity 3

					# Throw terminating error
					$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
					$PSCmdlet.ThrowTerminatingError($ErrorRecord)
				}

				# Attempt to read TSEnvironment variable MDMTenantName
				$Script:TenantName = $TSEnvironment.Value("MDMTenantName")
				if (-not ([string]::IsNullOrEmpty($Script:TenantName))) {
					Write-CMLogEntry -Value " - Successfully read client identification for AdminService through CMG from TS environment variable 'MDMTenantName': $($Script:TenantName)" -Severity 1
				} else {
					Write-CMLogEntry -Value " - Required client identification for AdminService through CMG could not be determined from TS environment variable" -Severity 3

					# Throw terminating error
					$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
					$PSCmdlet.ThrowTerminatingError($ErrorRecord)
				}

				# Attempt to read TSEnvironment variable MDMApplicationIDURI
				$Script:ApplicationIDURI = $TSEnvironment.Value("MDMApplicationIDURI")
				if (-not ([string]::IsNullOrEmpty($Script:ApplicationIDURI))) {
					Write-CMLogEntry -Value " - Successfully read Application ID URI from TS environment variable 'MDMApplicationIDURI': $($Script:ApplicationIDURI)" -Severity 1
				} else {
					Write-CMLogEntry -Value " - Using standard Application ID URI value: https://ConfigMgrService" -Severity 2
					$Script:ApplicationIDURI = "https://ConfigMgrService"
				}
			}
		}
	}

	function Get-AdminServiceEndpointType {
		switch ($Script:DeploymentMode) {
			"BareMetal" {
				$SMSInWinPE = $TSEnvironment.Value("_SMSTSInWinPE")
				if ($SMSInWinPE -eq $true) {
					Write-CMLogEntry -Value " - Detected that script was running within a task sequence in WinPE phase, automatically configuring AdminService endpoint type" -Severity 1
					$Script:AdminServiceEndpointType = "Internal"
				} else {
					Write-CMLogEntry -Value " - Detected that script was not running in WinPE of a bare metal deployment type, this is not a supported scenario" -Severity 3

					# Throw terminating error
					$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
					$PSCmdlet.ThrowTerminatingError($ErrorRecord)
				}
			}
			"Debug" {
				$Script:AdminServiceEndpointType = "Internal"
			}
			default {
				Write-CMLogEntry -Value " - Attempting to determine AdminService endpoint type based on current active Management Point candidates and from ClientInfo class" -Severity 1

				# Determine active MP candidates and if
				$ActiveMPCandidates = Get-CimInstance -Namespace "root\ccm\LocationServices" -ClassName "SMS_ActiveMPCandidate"
				$ActiveMPInternalCandidatesCount = ($ActiveMPCandidates | Where-Object {
						$PSItem.Type -like "Assigned"
					} | Measure-Object).Count
				$ActiveMPExternalCandidatesCount = ($ActiveMPCandidates | Where-Object {
						$PSItem.Type -like "Internet"
					} | Measure-Object).Count

				# Determine if ConfigMgr client has detected if the computer is currently on internet or intranet
				$CMClientInfo = Get-CimInstance -Namespace "root\ccm" -ClassName "ClientInfo"
				switch ($CMClientInfo.InInternet) {
					$true {
						if ($ActiveMPExternalCandidatesCount -ge 1) {
							$Script:AdminServiceEndpointType = "External"
						} else {
							Write-CMLogEntry -Value " - Detected as an Internet client but unable to determine External AdminService endpoint, bailing out" -Severity 3

							# Throw terminating error
							$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
							$PSCmdlet.ThrowTerminatingError($ErrorRecord)
						}
					}
					$false {
						if ($ActiveMPInternalCandidatesCount -ge 1) {
							$Script:AdminServiceEndpointType = "Internal"
						} else {
							Write-CMLogEntry -Value " - Detected as an Intranet client but unable to determine Internal AdminService endpoint, bailing out" -Severity 3

							# Throw terminating error
							$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
							$PSCmdlet.ThrowTerminatingError($ErrorRecord)
						}
					}
				}
			}
		}
		Write-CMLogEntry -Value " - Determined AdminService endpoint type as: $($AdminServiceEndpointType)" -Severity 1
	}

	function Set-AdminServiceEndpointURL {
		switch ($Script:AdminServiceEndpointType) {
			"Internal" {
				$Script:AdminServiceURL = "https://{0}/AdminService/wmi" -f $Endpoint
			}
			"External" {
				$Script:AdminServiceURL = "{0}/wmi" -f $ExternalEndpoint
			}
		}
		Write-CMLogEntry -Value " - Setting 'AdminServiceURL' variable to: $($Script:AdminServiceURL)" -Severity 1
	}

	function Get-AuthToken {
		$TokenRequest = $null
		$TokenResponse = $null
		try {
			# Retrieve OAuth directly so deployment never installs or executes a gallery module as SYSTEM.
			Write-CMLogEntry -Value " - Attempting to retrieve authentication token using native client with ID: $($ClientID)" -Severity 1
			$TenantIdentifier = [Uri]::EscapeDataString($TenantName.Trim())
			$TokenUri = "https://login.microsoftonline.com/$($TenantIdentifier)/oauth2/token"
			$TokenRequest = @{
				grant_type = "password"
				client_id = $ClientID
				resource = $ApplicationIDURI
				username = $Credential.UserName
				password = $Script:Password
			}
			$TokenResponse = Invoke-RestMethod -Method Post -Uri $TokenUri -Body $TokenRequest -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
			if ([string]::IsNullOrWhiteSpace($TokenResponse.token_type) -or [string]::IsNullOrWhiteSpace($TokenResponse.access_token)) {
				throw "The Microsoft identity platform response did not contain a token type and access token"
			}
			$Script:AuthToken = @{
				Authorization = "$($TokenResponse.token_type) $($TokenResponse.access_token)"
			}
			Write-CMLogEntry -Value " - Successfully retrieved authentication token" -Severity 1
		} catch [System.Exception] {
			Write-CMLogEntry -Value " - Failed to retrieve authentication token. Error message: $($PSItem.Exception.Message)" -Severity 3

			# Throw terminating error
			$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		} finally {
			if ($null -ne $TokenRequest) {
				$TokenRequest.password = $null
			}
			if ($null -ne $TokenResponse) {
				$TokenResponse.access_token = $null
			}
			$Script:Password = $null
			$Script:Credential = $null
		}
	}

	function Get-AuthDomainName {
		<#
		.SYNOPSIS
			Determine the Active Directory DNS domain name used to qualify a non-UPN service account.

		.DESCRIPTION
			Returns an empty string when no domain name can be determined, in which case the configured
			user name is used exactly as supplied. Sources are attempted in order of how explicitly they
			state the AD DNS domain, so a value the operator has configured always wins over one that is
			inferred from a host name.
		#>
		# 1. Task sequence domain join variables -- these are the AD DNS domain by definition
		if ($null -ne $Script:TSEnvironment) {
			foreach ($VariableName in @("OSDDOMAINNAME", "OSDJoinDomainName")) {
				try {
					$VariableValue = $Script:TSEnvironment.Value($VariableName)
				}
				catch [System.Exception] {
					$VariableValue = [string]::Empty
				}
				if ((-not [string]::IsNullOrWhiteSpace($VariableValue)) -and ($VariableValue -match "\.")) {
					return $VariableValue.Trim()
				}
			}
		}

		# 2. Domain membership of the running device -- available in full OS deployment types, but not
		#    in WinPE where the computer is always reported as a workgroup member
		try {
			$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
			if (($ComputerSystem.PartOfDomain -eq $true) -and ($ComputerSystem.Domain -match "\.")) {
				return $ComputerSystem.Domain
			}
		}
		catch [System.Exception] {
			# Fall through to the host name based sources below
		}

		# 3. DNS suffix of the site server hosting the AdminService and of the management point, e.g.
		#    'CM01.corp.contoso.com' yields 'corp.contoso.com'. Available in WinPE, where neither of
		#    the sources above is, and correct wherever the site server shares the account's domain.
		$HostNameSources = New-Object -TypeName System.Collections.ArrayList
		foreach ($EndpointValue in @($Script:Endpoint, $Script:ExternalEndpoint)) {
			if (-not [string]::IsNullOrWhiteSpace($EndpointValue)) {
				$null = $HostNameSources.Add($EndpointValue)
			}
		}
		if ($null -ne $Script:TSEnvironment) {
			try {
				$ManagementPoint = $Script:TSEnvironment.Value("_SMSTSMP")
			}
			catch [System.Exception] {
				$ManagementPoint = [string]::Empty
			}
			if (-not [string]::IsNullOrWhiteSpace($ManagementPoint)) {
				$null = $HostNameSources.Add($ManagementPoint)
			}
		}
		foreach ($HostNameSource in $HostNameSources) {
			$HostName = ((($HostNameSource -replace "^https?://", "") -split "/")[0] -split ":")[0]
			if ($HostName -match "^[^\.]+\.(?<Suffix>.+)$") {
				return $Matches.Suffix
			}
		}

		return [string]::Empty
	}

	function Get-AuthUserNameCandidate {
		<#
		.SYNOPSIS
			Build the ordered list of user name formats to attempt against the AdminService.

		.DESCRIPTION
			The configured value is always first, so an environment that authenticates today is never
			altered. It is followed by the UPN form (user@domain.com) and then the down-level logon
			form (DOMAIN\user), both built from the detected AD DNS domain. Duplicates are removed, so
			a value already in UPN form simply yields fewer candidates.
		#>
		param (
			[parameter(Mandatory = $true, HelpMessage = "Specify the configured service account user name.")]
			[ValidateNotNullOrEmpty()]
			[string]$UserName
		)
		$Candidates = New-Object -TypeName System.Collections.ArrayList
		$null = $Candidates.Add($UserName)

		# Split the configured value into its account name and whatever domain qualifier it carries
		$DomainName = Get-AuthDomainName
		if ($UserName -match "^(?<Domain>[^\\]+)\\(?<Account>.+)$") {
			$AccountName = $Matches.Account
			$NetBIOSName = $Matches.Domain
		}
		elseif ($UserName -match "^(?<Account>[^@]+)@(?<Suffix>.+)$") {
			$AccountName = $Matches.Account
			$NetBIOSName = ($Matches.Suffix -split "\.")[0]
			if ([string]::IsNullOrWhiteSpace($DomainName)) {
				$DomainName = $Matches.Suffix
			}
		}
		else {
			$AccountName = $UserName
			$NetBIOSName = [string]::Empty
		}

		# UPN form -- the preferred unambiguous domain-qualified format
		if (-not [string]::IsNullOrWhiteSpace($DomainName)) {
			$UserPrincipalName = "$($AccountName)@$($DomainName)"
			if ($Candidates -notcontains $UserPrincipalName) {
				$null = $Candidates.Add($UserPrincipalName)
			}
			if ([string]::IsNullOrWhiteSpace($NetBIOSName)) {
				$NetBIOSName = ($DomainName -split "\.")[0]
			}
		}

		# Down-level logon form, for sites that still accept it
		if (-not [string]::IsNullOrWhiteSpace($NetBIOSName)) {
			$DownLevelName = "$($NetBIOSName)\$($AccountName)"
			if ($Candidates -notcontains $DownLevelName) {
				$null = $Candidates.Add($DownLevelName)
			}
		}

		# Handle return value
		return $Candidates
	}

	function New-AuthCredential {
		[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "", Justification = "The task-sequence password is converted only in memory to the PSCredential required for AdminService authentication and is not persisted.")]
		param (
			[parameter(Mandatory = $true, HelpMessage = "Specify the user name to construct a credential object for.")]
			[ValidateNotNullOrEmpty()]
			[string]$UserName
		)
		$EncryptedPassword = ConvertTo-SecureString -String $Script:Password -AsPlainText -Force

		# Handle return value
		return (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($UserName, $EncryptedPassword))
	}

	function Test-AuthenticationFailure {
		<#
		.SYNOPSIS
			Determine whether an AdminService request failed because the credentials were rejected.

		.DESCRIPTION
			Only a rejected authentication justifies retrying with a different user name format. The
			HTTP status code is used where the exception carries a response; the message is only
			inspected as a fallback, since its wording is localised.
		#>
		param (
			[parameter(Mandatory = $false, HelpMessage = "Specify the error record from the failed AdminService request.")]
			$ErrorRecord
		)
		if ($null -eq $ErrorRecord) {
			return $false
		}
		try {
			$Response = $ErrorRecord.Exception.Response
			if (($null -ne $Response) -and ($null -ne $Response.StatusCode)) {
				if ([int]$Response.StatusCode -eq 401) {
					return $true
				}

				# A response carrying any other status code is a definitive non-authentication failure
				return $false
			}
		}
		catch [System.Exception] {
			# Fall through to the message based check below
		}

		# Handle return value
		return ($ErrorRecord.Exception.Message -match "\(401\)|Unauthorized")
	}
	function Get-AuthCredential {
		# Construct PSCredential object for authentication
		$Script:Credential = New-AuthCredential -UserName $Script:UserName

		# Build an ordered list of user name formats to attempt when an environment rejects the
		# configured value with 401 Unauthorized. Microsoft does not document a ConfigMgr 2603
		# UPN-only requirement, so always try the configured value first.
		$Script:CredentialCandidates = Get-AuthUserNameCandidate -UserName $Script:UserName
		if ($Script:UserName -notmatch "@") {
			Write-CMLogEntry -Value " - The service account user name is not in UPN format. If the configured value is rejected, domain-qualified alternatives will be attempted; UPN format (user@domain.com) is recommended to avoid ambiguity" -Severity 2
			if (($Script:CredentialCandidates | Measure-Object).Count -gt 1) {
				$AlternativeNames = ($Script:CredentialCandidates | Select-Object -Skip 1 | ForEach-Object { ConvertTo-ObfuscatedUserName -InputObject $PSItem }) -join ", "
				Write-CMLogEntry -Value " - Alternative user name formats will be attempted automatically if the configured value is rejected: $($AlternativeNames)" -Severity 2
			}
			else {
				Write-CMLogEntry -Value " - Unable to determine the Active Directory DNS domain name, no alternative user name formats can be attempted if the configured value is rejected" -Severity 2
			}
		}
	}

	function Get-AdminServiceItem {
		param (
			[parameter(Mandatory = $true, HelpMessage = "Specify the resource for the AdminService API call, e.g. '/SMS_Package'.")]
			[ValidateNotNullOrEmpty()]
			[string]$Resource
		)
		# Construct array object to hold return value
		$PackageArray = New-Object -TypeName System.Collections.ArrayList

		switch ($Script:AdminServiceEndpointType) {
			"External" {
				try {
					$AdminServiceUri = $AdminServiceURL + $Resource
					Write-CMLogEntry -Value " - Calling AdminService endpoint with URI: $($AdminServiceUri)" -Severity 1
					$AdminServiceResponse = Invoke-RestMethod -Method Get -Uri $AdminServiceUri -Headers $AuthToken -ErrorAction Stop
				} catch [System.Exception] {
					Write-CMLogEntry -Value " - Failed to retrieve available package items from AdminService endpoint. Error message: $($PSItem.Exception.Message)" -Severity 3

					# Throw terminating error
					$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
					$PSCmdlet.ThrowTerminatingError($ErrorRecord)
				}
			}
			"Internal" {
				$AdminServiceUri = $AdminServiceURL + $Resource
				Write-CMLogEntry -Value " - Calling AdminService endpoint with URI: $($AdminServiceUri)" -Severity 1

				# Attempt each user name format in turn. The configured value is always first, so a
				# working environment is unaffected; the domain qualified alternatives are only used
				# after the AdminService rejects the credentials with 401 Unauthorized.
				$CandidateList = @($Script:CredentialCandidates)
				if ($CandidateList.Count -eq 0) {
					$CandidateList = @($Script:UserName)
				}
				$RequestSucceeded = $false
				$LastErrorRecord = $null

				for ($CandidateIndex = 0; $CandidateIndex -lt $CandidateList.Count; $CandidateIndex++) {
					$CandidateUserName = $CandidateList[$CandidateIndex]
					$CandidateCredential = New-AuthCredential -UserName $CandidateUserName
					$LastErrorRecord = $null
					if ($CandidateIndex -gt 0) {
						Write-CMLogEntry -Value " - Retrying AdminService endpoint connection using alternative user name format: $(ConvertTo-ObfuscatedUserName -InputObject $CandidateUserName)" -Severity 2
					}

					try {
						# Call AdminService endpoint to retrieve package data
						$AdminServiceResponse = Invoke-RestMethod -Method Get -Uri $AdminServiceUri -Credential $CandidateCredential -ErrorAction Stop
						$RequestSucceeded = $true
					}
					catch {
						$LastErrorRecord = $PSItem
					}

					if ($RequestSucceeded -eq $true) {
						# Persist the working credential so any further calls in this run authenticate directly
						$Script:Credential = $CandidateCredential
						if ($CandidateIndex -gt 0) {
							Write-CMLogEntry -Value " - Successfully authenticated against the AdminService using user name format: $(ConvertTo-ObfuscatedUserName -InputObject $CandidateUserName)" -Severity 2
							Write-CMLogEntry -Value " - WARNING: Update the service account user name to the UPN format (user@domain.com) to avoid these additional authentication attempts" -Severity 2
						}
						break
					}

					# Only a rejected authentication justifies attempting another user name format
					if (-not (Test-AuthenticationFailure -ErrorRecord $LastErrorRecord)) {
						break
					}
					Write-CMLogEntry -Value " - AdminService endpoint rejected the credentials for user name: $(ConvertTo-ObfuscatedUserName -InputObject $CandidateUserName)" -Severity 2
				}

				if ($RequestSucceeded -eq $false) {
					$FailureMessage = if ($null -ne $LastErrorRecord) { $LastErrorRecord.Exception.Message } else { "No response was returned from the AdminService endpoint" }
					Write-CMLogEntry -Value " - Failed to retrieve available package items from AdminService endpoint. Error message: $($FailureMessage)" -Severity 3
					if (Test-AuthenticationFailure -ErrorRecord $LastErrorRecord) {
						Write-CMLogEntry -Value " - All attempted user name formats were rejected by the AdminService. Verify the credentials, account policy, endpoint configuration, and accepted user name format; prefer UPN format (user@domain.com) for the MDMUserName task sequence variable or UserName parameter" -Severity 3
					}

					# Throw terminating error
					$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
					$PSCmdlet.ThrowTerminatingError($ErrorRecord)
				}
			}
		}

		# Add returned BIOS package objects to array list
		if ($null -ne $AdminServiceResponse.value) {
			foreach ($Package in $AdminServiceResponse.value) {
				$PackageArray.Add($Package) | Out-Null
			}
		}

		# Handle return value
		return $PackageArray
	}

	function Get-BIOSPackages {
		try {
			# Retrieve BIOS packages but filter out matches depending on script operational mode
			switch ($OperationalMode) {
				"Production" {
					if ($Script:PSCmdlet.ParameterSetName -like "XMLPackage") {
						Write-CMLogEntry -Value " - Reading XML content logic file BIOS package entries" -Severity 1
						$Packages = (([xml]$(Get-Content -Path $XMLPackageLogicFile -Raw)).ArrayOfCMPackage).CMPackage | Where-Object {
							$_.Name -notmatch "Pilot" -and $_.Name -notmatch "Legacy" -and $_.Name -match $Filter
						}
					} else {
						Write-CMLogEntry -Value " - Querying AdminService for BIOS package instances" -Severity 1
						$Packages = Get-AdminServiceItem -Resource "/SMS_Package?`$filter=contains(Name,'$($Filter)')" | Where-Object {
							$_.Name -notmatch "Pilot" -and $_.Name -notmatch "Retired"
						}
					}

				}
				"Pilot" {
					if ($Script:PSCmdlet.ParameterSetName -like "XMLPackage") {
						Write-CMLogEntry -Value " - Reading XML content logic file BIOS package entries" -Severity 1
						$Packages = (([xml]$(Get-Content -Path $XMLPackageLogicFile -Raw)).ArrayOfCMPackage).CMPackage | Where-Object {
							$_.Name -match "Pilot" -and $_.Name -match $Filter
						}
					} else {
						Write-CMLogEntry -Value " - Querying AdminService for BIOS package instances" -Severity 1
						$Packages = Get-AdminServiceItem -Resource "/SMS_Package?`$filter=contains(Name,'$($Filter)')" | Where-Object {
							$_.Name -match "Pilot"
						}
					}
				}
			}

			# Handle return value
			if ($null -ne $Packages) {
				Write-CMLogEntry -Value " - Retrieved a total of '$(($Packages | Measure-Object).Count)' BIOS packages from $($Script:PackageSource) matching operational mode: $($OperationalMode)" -Severity 1
				return $Packages
			} else {
				Write-CMLogEntry -Value " - Retrieved a total of '0' BIOS packages from $($Script:PackageSource) matching operational mode: $($OperationalMode)" -Severity 3

				# Throw terminating error
				$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
		} catch [System.Exception] {
			Write-CMLogEntry -Value " - An error occurred while calling $($Script:PackageSource) for a list of available BIOS packages. Error message: $($_.Exception.Message)" -Severity 3

			# Throw terminating error
			$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
	}

	function Get-ComputerData {
		# Create a custom object for computer details gathered from local WMI
		$ComputerDetails = [PSCustomObject]@{
			Manufacturer = $null
			Model = $null
			SystemSKU = $null
			FallbackSKU = $null
		}

		# Gather computer details based upon specific computer manufacturer
		$ComputerManufacturer = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()

		# Wrapped in try/catch so a failure in any manufacturer-specific WMI/parse step (e.g. a null
		# BaseBoardProduct, a short Lenovo Model for SubString, or a Dell OEMString without a bracketed
		# SKU) is logged with the manufacturer context, instead of surfacing only as a generic error
		# later, and so a non-critical sub-step failure does not abort detection.
		try {
		switch -Wildcard ($ComputerManufacturer) {
			"*Microsoft*" {
				$ComputerDetails.Manufacturer = "Microsoft"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				$ComputerDetails.SystemSKU = Get-CimInstance -Namespace "root\wmi" -ClassName "MS_SystemInformation" | Select-Object -ExpandProperty SystemSKU
			}
			"*HP*" {
				$ComputerDetails.Manufacturer = "HP"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				$ComputerDetails.SystemSKU = (Get-CIMInstance -ClassName "MS_SystemInformation" -NameSpace "root\WMI").BaseBoardProduct.Trim()
			}
			"*Hewlett-Packard*" {
				$ComputerDetails.Manufacturer = "HP"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				$ComputerDetails.SystemSKU = (Get-CIMInstance -ClassName "MS_SystemInformation" -NameSpace "root\WMI").BaseBoardProduct.Trim()
			}
			"*Dell*" {
				$ComputerDetails.Manufacturer = "Dell"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				$ComputerDetails.SystemSKU = (Get-CIMInstance -ClassName "MS_SystemInformation" -NameSpace "root\WMI").SystemSku.Trim()
				[string]$OEMString = Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty OEMStringArray
				$ComputerDetails.FallbackSKU = [regex]::Matches($OEMString, '\[\S*]')[0].Value.TrimStart("[").TrimEnd("]")
			}
			"*Lenovo*" {
				$ComputerDetails.Manufacturer = "Lenovo"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystemProduct" | Select-Object -ExpandProperty Version).Trim()
				$ComputerDetails.SystemSKU = ((Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).SubString(0, 4)).Trim()
			}
			"*Panasonic*" {
				$ComputerDetails.Manufacturer = "Panasonic Corporation"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				$ComputerDetails.SystemSKU = (Get-CIMInstance -ClassName "MS_SystemInformation" -NameSpace "root\WMI").BaseBoardProduct.Trim()
			}
			"*Viglen*" {
				$ComputerDetails.Manufacturer = "Viglen"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				$ComputerDetails.SystemSKU = (Get-CimInstance -ClassName "Win32_BaseBoard" | Select-Object -ExpandProperty SKU).Trim()
			}
			"*AZW*" {
				$ComputerDetails.Manufacturer = "AZW"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				$ComputerDetails.SystemSKU = (Get-CIMInstance -ClassName "MS_SystemInformation" -NameSpace root\WMI).BaseBoardProduct.Trim()
			}
			"*Fujitsu*" {
				$ComputerDetails.Manufacturer = "Fujitsu"
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				$ComputerDetails.SystemSKU = (Get-CimInstance -ClassName "Win32_BaseBoard" | Select-Object -ExpandProperty SKU).Trim()
			}
			default {
				# =============================================================================
				# CUSTOM / UNLISTED MANUFACTURER -- ADD SUPPORT HERE
				# -----------------------------------------------------------------------------
				# This default branch is reached when the detected Win32_ComputerSystem
				# Manufacturer value does not match any of the wildcards above. It performs a
				# best-effort generic detection (Manufacturer + Model only) so that
				# ComputerModel-based package matching can still work, and logs a warning that
				# the manufacturer is not explicitly supported.
				#
				# To add full support for a new manufacturer, copy the template below into its
				# own "*<Manufacturer>*" branch above. The wildcard must match the value reported
				# by:  (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
				# Populate the three key properties from the correct WMI/CIM source for that OEM.
				# The SystemSKU source differs per vendor -- for example:
				#   Dell     -> (Get-CIMInstance -ClassName MS_SystemInformation -Namespace root\WMI).SystemSku
				#   HP       -> (Get-CIMInstance -ClassName MS_SystemInformation -Namespace root\WMI).BaseBoardProduct
				#   Lenovo   -> first 4 characters of Win32_ComputerSystem.Model (the machine type)
				#   Others   -> Win32_BaseBoard SKU or Product
				#
				# Template (add as a new branch above and adjust the values):
				#   "*Acme*" {
				#       $ComputerDetails.Manufacturer = "Acme"
				#       $ComputerDetails.Model        = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				#       $ComputerDetails.SystemSKU    = (Get-CimInstance -ClassName "Win32_BaseBoard" | Select-Object -ExpandProperty SKU).Trim()
				#   }
				#
				# IMPORTANT: adding a branch here is not sufficient on its own. The new
				# manufacturer name must ALSO be added to the $Manufacturers allow-list inside
				# the Get-BIOSUpdate function, otherwise any matched packages are filtered out.
				# =============================================================================
				$ComputerDetails.Manufacturer = $ComputerManufacturer
				$ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
				# SystemSKU intentionally left unset -- add the correct source for this OEM using the template above.
				Write-CMLogEntry -Value " - Manufacturer '$($ComputerManufacturer)' is not explicitly supported. Using best-effort model detection only. To add full support, see the CUSTOM / UNLISTED MANUFACTURER template in the Get-ComputerData function and add the manufacturer to the `$Manufacturers allow-list in Get-BIOSUpdate." -Severity 2
			}
		}
		}
		catch [System.Exception] {
			Write-CMLogEntry -Value " - An error occurred while gathering computer details for manufacturer '$($ComputerManufacturer)'. Error message: $($_.Exception.Message)" -Severity 3
			# Best-effort fallback so downstream computer-model matching can still proceed.
			if ([string]::IsNullOrEmpty($ComputerDetails.Manufacturer)) { $ComputerDetails.Manufacturer = $ComputerManufacturer }
			if ([string]::IsNullOrEmpty($ComputerDetails.Model)) {
				try { $ComputerDetails.Model = (Get-CimInstance -ClassName "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim() } catch { Write-CMLogEntry -Value " - Unable to determine computer model during fallback. Error message: $($_.Exception.Message)" -Severity 3 }
			}
		}

		# Handle overriding computer details if debug mode and additional parameters was specified
		if ($Script:PSCmdlet.ParameterSetName -like "Debug") {
			if (-not ([string]::IsNullOrEmpty($Manufacturer))) {
				$ComputerDetails.Manufacturer = $Manufacturer
			}
			if (-not ([string]::IsNullOrEmpty($ComputerModel))) {
				$ComputerDetails.Model = $ComputerModel
			}
			if (-not ([string]::IsNullOrEmpty($SystemSKU))) {
				$ComputerDetails.SystemSKU = $SystemSKU
			}
		}

		# Handle output to log file for computer details
		Write-CMLogEntry -Value " - Computer manufacturer determined as: $($ComputerDetails.Manufacturer)" -Severity 1
		Write-CMLogEntry -Value " - Computer model determined as: $($ComputerDetails.Model)" -Severity 1

		# Handle output to log file for computer SystemSKU
		if (-not ([string]::IsNullOrEmpty($ComputerDetails.SystemSKU))) {
			Write-CMLogEntry -Value " - Computer SystemSKU determined as: $($ComputerDetails.SystemSKU)" -Severity 1
		} else {
			Write-CMLogEntry -Value " - Computer SystemSKU determined as: <null>" -Severity 2
		}

		# Handle output to log file for Fallback SKU
		if (-not ([string]::IsNullOrEmpty($ComputerDetails.FallBackSKU))) {
			Write-CMLogEntry -Value " - Computer Fallback SystemSKU determined as: $($ComputerDetails.FallBackSKU)" -Severity 1
		}

		# Handle return value from function
		return $ComputerDetails
	}

	function Test-VirtualMachinePlatform {
		param (
			[parameter(Mandatory = $false, HelpMessage = "Specify the Win32_ComputerSystem Model value to be evaluated.")]
			[AllowEmptyString()]
			[AllowNull()]
			[string]$Model,
			[parameter(Mandatory = $false, HelpMessage = "Specify the Win32_ComputerSystem Manufacturer value to be evaluated.")]
			[AllowEmptyString()]
			[AllowNull()]
			[string]$Manufacturer
		)
		# Single source of truth for virtual platform detection. Previously this list was duplicated in
		# two locations with divergent entries, which meant a VMware guest could pass one gate and fail
		# the other. Virtual machines expose no physical firmware flash chip, so they are never valid
		# BIOS update targets.
		$VirtualMachineModels = @(
			"Virtual Machine", # Hyper-V
			"VMware Virtual Platform", "VMware7,1", "VMware20,1", "VMware Virtual Platform None", # VMware
			"VirtualBox", # Oracle VirtualBox
			"HVM domU", # Xen / AWS EC2
			"KVM", "QEMU Virtual Machine", "Standard PC (Q35 + ICH9, 2009)", "Standard PC (i440FX + PIIX, 1996)", # KVM / QEMU / Proxmox
			"Parallels Virtual Platform", # Parallels
			"Google Compute Engine", # GCP
			"AHV" # Nutanix
		)
		if ($Model -in $VirtualMachineModels) {
			return $true
		}

		# Manufacturer based detection catches hypervisor hardware revisions that are not yet in the model
		# list above. "Microsoft Corporation" is deliberately excluded since it is also reported by Surface.
		if (-not([string]::IsNullOrEmpty($Manufacturer))) {
			if ($Manufacturer -match "VMware|QEMU|innotek|Xen|Parallels|Nutanix|Red Hat|Google|Amazon EC2|OpenStack") {
				return $true
			}
		}

		return $false
	}

	function Test-SecureBootCertificateStatus {
		# Reports Secure Boot certificate posture ahead of the 2026 expiry of the original 2011 Microsoft
		# certificates. Strictly read-only and non-terminating: Windows servicing coordinates the transition
		# with physical or virtual firmware, and some platforms also require an OEM or hypervisor update.
		# Presence of Windows UEFI CA 2023 in DB is useful but does not by itself prove the complete transition;
		# Microsoft defines UEFICA2023Status=Updated as completion of all keys and the new boot manager.
		$CertificatePresent = $false
		$CertificateStatus = "Unknown"

		try {
			if ($null -eq (Get-Command -Name "Confirm-SecureBootUEFI" -ErrorAction SilentlyContinue)) {
				$CertificateStatus = "Unavailable"
				Write-CMLogEntry -Value " - Secure Boot cmdlets are not available on this platform, skipping Secure Boot certificate check" -Severity 2
			} elseif ((Confirm-SecureBootUEFI -ErrorAction Stop) -ne $true) {
				$CertificateStatus = "Disabled"
				Write-CMLogEntry -Value " - Secure Boot is not enabled, skipping Secure Boot certificate check" -Severity 2
			} else {
				$SignatureDatabase = Get-SecureBootUEFI -Name "db" -ErrorAction Stop
				$SignatureDatabaseText = [System.Text.Encoding]::ASCII.GetString($SignatureDatabase.Bytes)
				if ($SignatureDatabaseText -match "Windows UEFI CA 2023") {
					$CertificatePresent = $true
					$ServicingState = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023Status" -ErrorAction SilentlyContinue
					if ($ServicingState.UEFICA2023Status -eq "Updated") {
						$CertificateStatus = "Updated"
						Write-CMLogEntry -Value " - Secure Boot 2023 certificate transition is complete (UEFICA2023Status=Updated)" -Severity 1
					} else {
						$CertificateStatus = "Present"
						Write-CMLogEntry -Value " - Secure Boot signature database contains 'Windows UEFI CA 2023', but the complete certificate and boot manager transition is not confirmed" -Severity 2
					}
				} else {
					$CertificateStatus = "NotPresent"
					Write-CMLogEntry -Value " - Secure Boot signature database does not contain 'Windows UEFI CA 2023'. The 2011 certificates expire in 2026, remediate through Windows servicing and any required OEM or hypervisor update" -Severity 2
				}
			}
		} catch [System.Exception] {
			$CertificateStatus = "Error"
			Write-CMLogEntry -Value " - Unable to determine Secure Boot certificate status. Error message: $($_.Exception.Message)" -Severity 2
		}

		if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
			$TSEnvironment.Value("SecureBootCertificate2023Present") = $CertificatePresent
			$TSEnvironment.Value("SecureBootCertificate2023Status") = $CertificateStatus
		}
	}

	function Get-ComputerSystemType {
		$ComputerSystem = Get-CimInstance -ClassName "Win32_ComputerSystem"
		if (-not(Test-VirtualMachinePlatform -Model $ComputerSystem.Model -Manufacturer $ComputerSystem.Manufacturer)) {
			Write-CMLogEntry -Value " - Supported computer platform detected, script execution allowed to continue" -Severity 1
		} else {
			if ($Script:PSCmdlet.ParameterSetName -like "Debug") {
				Write-CMLogEntry -Value " - Unsupported computer platform detected, virtual machines are not supported but will be allowed in DebugMode" -Severity 2
			} else {
				Write-CMLogEntry -Value " - Unsupported computer platform detected, virtual machines are not supported" -Severity 3

				# Throw terminating error
				$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
		}
	}

	function Test-ComputerDetails {
		param (
			[parameter(Mandatory = $true, HelpMessage = "Specify the computer details object from Get-ComputerDetails function.")]
			[ValidateNotNullOrEmpty()]
			[PSCustomObject]$InputObject
		)
		# Construct custom object for computer details validation
		$Script:ComputerDetection = [PSCustomObject]@{
			"ModelDetected" = $false
			"SystemSKUDetected" = $false
		}

		if (($null -ne $InputObject.Model) -and (-not ([System.String]::IsNullOrEmpty($InputObject.Model)))) {
			Write-CMLogEntry -Value " - Computer model detection was successful" -Severity 1
			$ComputerDetection.ModelDetected = $true
		}

		if (($null -ne $InputObject.SystemSKU) -and (-not ([System.String]::IsNullOrEmpty($InputObject.SystemSKU)))) {
			Write-CMLogEntry -Value " - Computer SystemSKU detection was successful" -Severity 1
			$ComputerDetection.SystemSKUDetected = $true
		}

		if (($ComputerDetection.ModelDetected -eq $false) -and ($ComputerDetection.SystemSKUDetected -eq $false)) {
			Write-CMLogEntry -Value " - Computer model and SystemSKU values are missing, script execution is not allowed since required values to continue could not be gathered" -Severity 3

			# Throw terminating error
			$ErrorRecord = New-TerminatingErrorRecord -Message ([string]::Empty)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		} else {
			Write-CMLogEntry -Value " - Computer details successfully verified" -Severity 1
		}
	}

	function Set-ComputerDetectionMethod {
		if ($ComputerDetection.SystemSKUDetected -eq $true) {
			Write-CMLogEntry -Value " - Determined primary computer detection method: SystemSKU" -Severity 1
			return "SystemSKU"
		} else {
			Write-CMLogEntry -Value " - Determined fallback computer detection method: ComputerModel" -Severity 1
			return "ComputerModel"
		}
	}

	function Compare-BIOSVersion {
		param (
			[parameter(Mandatory = $false, HelpMessage = "Current available BIOS version.")]
			[ValidateNotNullOrEmpty()]
			[string]$AvailableBIOSVersion,
			[parameter(Mandatory = $false, HelpMessage = "Current available BIOS revision date.")]
			[string]$AvailableBIOSReleaseDate,
			[parameter(Mandatory = $true, HelpMessage = "Current available BIOS version.")]
			[ValidateNotNullOrEmpty()]
			[string]$ComputerManufacturer
		)

		if ($ComputerManufacturer -match "Dell") {
			# Obtain current BIOS release
			$CurrentBIOSVersion = (Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
			Write-CMLogEntry -Value "Current BIOS release detected as $($CurrentBIOSVersion)." -Severity 1
			Write-CMLogEntry -Value "Available BIOS release deteced as $($AvailableBIOSVersion)." -Severity 1

			# Determine Dell BIOS revision format
			if ($CurrentBIOSVersion -like "*.*.*") {
				# Compare current BIOS release to available
				if ([System.Version]$AvailableBIOSVersion -gt [System.Version]$CurrentBIOSVersion) {
					# Write output to task sequence variable
					if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
						$TSEnvironment.Value("NewBIOSAvailable") = $true
					}
					Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
				}
			} elseif ($CurrentBIOSVersion -match "^A(?<CurrentRevision>\d+)$") {
				$CurrentRevision = [int]$Matches.CurrentRevision
				# Compare current BIOS release to available
				if ($AvailableBIOSVersion -like "*.*.*") {
					# Assume that the bios is new as moving from Axx to x.x.x formats
					# Write output to task sequence variable
					if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
						$TSEnvironment.Value("NewBIOSAvailable") = $true
					}
					Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
				} elseif ($AvailableBIOSVersion -match "^A(?<AvailableRevision>\d+)$" -and
					[int]$Matches.AvailableRevision -gt $CurrentRevision) {
					# Write output to task sequence variable
					if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
						$TSEnvironment.Value("NewBIOSAvailable") = $true
					}
					Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
				}
			}
		}

		if ($ComputerManufacturer -match "Lenovo") {
			# Obtain current BIOS release
			$CurrentBIOSReleaseDate = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).ReleaseDate.ToString("yyyyMMdd", [System.Globalization.CultureInfo]::InvariantCulture)
			Write-CMLogEntry -Value "Current BIOS release date detected as $($CurrentBIOSReleaseDate)." -Severity 1
			Write-CMLogEntry -Value "Available BIOS release date detected as $($AvailableBIOSReleaseDate)." -Severity 1

			# Compare current BIOS release to available
			if ($AvailableBIOSReleaseDate -gt $CurrentBIOSReleaseDate) {
				# Write output to task sequence variable
				if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
					$TSEnvironment.Value("NewBIOSAvailable") = $true
				}
				Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current date release dated $($CurrentBIOSReleaseDate) will be replaced by release $($AvailableBIOSReleaseDate)." -Severity 1
			}
		}

		if ($ComputerManufacturer -match "Hewlett-Packard|HP") {
			# Obtain current BIOS release
			$CurrentBIOSProperties = (Get-CimInstance -ClassName Win32_BIOS | Select-Object -Property *)

			# Update version formatting
			$AvailableBIOSVersion = $AvailableBIOSVersion.TrimEnd(".")
			$AvailableBIOSVersion = $AvailableBIOSVersion.Split(" ")[0]

			# Detect new versus old BIOS formats
			switch -wildcard ($($CurrentBIOSProperties.SMBIOSBIOSVersion)) {
				"*ver*" {
					if ($CurrentBIOSProperties.SMBIOSBIOSVersion -match '.F.\d+$') {
						$CurrentBIOSVersion = ($CurrentBIOSProperties.SMBIOSBIOSVersion -split "Ver.")[1].Trim()
						$BIOSVersionParseable = $false
					} else {
						$CurrentBIOSVersion = [System.Version]::Parse(($CurrentBIOSProperties.SMBIOSBIOSVersion).TrimStart($CurrentBIOSProperties.SMBIOSBIOSVersion.Split(".")[0]).TrimStart(".").Trim().Split(" ")[0])
						$BIOSVersionParseable = $true
					}
				}
				default {
					$CurrentBIOSVersion = "$($CurrentBIOSProperties.SystemBiosMajorVersion).$($CurrentBIOSProperties.SystemBiosMinorVersion)"
					$BIOSVersionParseable = $true
				}
			}

			# Output version details
			Write-CMLogEntry -Value "Current BIOS release detected as $($CurrentBIOSVersion)." -Severity 1
			Write-CMLogEntry -Value "Available BIOS release detected as $($AvailableBIOSVersion)." -Severity 1

			# Compare current BIOS release to available
			switch ($BIOSVersionParseable) {
				$true {
					if ([System.Version]$AvailableBIOSVersion -gt [System.Version]$CurrentBIOSVersion) {
						# Write output to task sequence variable
						if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
							$TSEnvironment.Value("NewBIOSAvailable") = $true
						}
						Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
					}
				}
				$false {
					if ([System.Int32]::Parse($AvailableBIOSVersion.TrimStart("F.")) -gt [System.Int32]::Parse($CurrentBIOSVersion.TrimStart("F."))) {
						# Write output to task sequence variable
						if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
							$TSEnvironment.Value("NewBIOSAvailable") = $true
						}
						Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
					}
				}
			}
		}
	}

	function Get-LenovoBIOSReleaseDate {
		# Lenovo BIOS packages encode the release date in the package description, in the form
		# "...:...:yyyyMMdd)". The original code called .Split(":")[2].TrimEnd(")") directly on the
		# description, which threw "You cannot call a method on a null-valued expression" whenever the
		# property was missing (notably the multiple-match branch, which read the non-existent
		# PackageDescription property instead of Description) or the description was not in the expected
		# shape. Return an empty string instead so the caller can degrade gracefully.
		param (
			[parameter(Mandatory = $false, HelpMessage = "Lenovo BIOS package object to extract the release date from.")]
			$Package
		)

		if ($null -eq $Package) {
			return [string]::Empty
		}

		# Prefer Description (the real SMS_Package property); fall back to PackageDescription for
		# compatibility with any caller still supplying the legacy shape.
		$DescriptionValue = $Package.Description
		if ([string]::IsNullOrEmpty($DescriptionValue)) {
			$DescriptionValue = $Package.PackageDescription
		}

		if ([string]::IsNullOrEmpty($DescriptionValue)) {
			Write-CMLogEntry -Value "Unable to determine the Lenovo BIOS release date, the package description is empty" -Severity 2
			return [string]::Empty
		}

		$DescriptionParts = $DescriptionValue -split ":"
		if ($DescriptionParts.Count -lt 3) {
			Write-CMLogEntry -Value "Unable to determine the Lenovo BIOS release date from package description: $($DescriptionValue)" -Severity 2
			return [string]::Empty
		}

		return ($DescriptionParts[2]).TrimEnd(")").Trim()
	}

	function Set-NewBIOSAvailableFlag {
		# Centralises writes to the NewBIOSAvailable task sequence variable so the Debug parameter set
		# never touches the task sequence environment.
		param (
			[parameter(Mandatory = $true, HelpMessage = "Value to assign to the NewBIOSAvailable task sequence variable.")]
			[bool]$Value
		)

		if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
			$TSEnvironment.Value("NewBIOSAvailable") = $Value
		}
	}

	function Get-BIOSUpdate {
		param (
			[parameter(Mandatory = $true, HelpMessage = "Specify the computer details object from Get-ComputerDetails function.")]
			[ValidateNotNullOrEmpty()]
			[PSCustomObject]$InputObject
		)

		# Define machine matching values
		$ComputerSystemType = $InputObject.Model
		$ComputerManufacturer = $InputObject.Manufacturer
		$SystemSKU = $InputObject.SystemSKU

		# Supported manufacturers
		$Manufacturers = @("Dell", "Hewlett-Packard", "Lenovo", "Microsoft", "HP")

		$PackageList = New-Object -TypeName System.Collections.ArrayList

		if (-not(Test-VirtualMachinePlatform -Model $ComputerSystemType -Manufacturer $ComputerManufacturer)) {
			# Process packages returned from web service
			if ($null -ne $BIOSPackages) {
				if (($null -ne $ComputerSystemType) -and (-not ([System.String]::IsNullOrEmpty($ComputerSystemType))) -or (($null -ne $SystemSKU) -and (-not ([System.String]::IsNullOrEmpty($SystemSKU))))) {
					# Determine computer model detection
					if ([System.String]::IsNullOrEmpty($SystemSKU)) {
						Write-CMLogEntry -Value "Attempting to find a match for BIOS package: $($Package.PackageName) ($($Package.PackageID))" -Severity 1
						Write-CMLogEntry -Value "Computer detection method set to use ComptuerModel" -Severity 1
						$ComputerDetectionMethod = "ComputerModel"
					} else {
						Write-CMLogEntry -Value "Attempting to find a match for BIOS package: $($Package.PackageName) ($($Package.PackageID))" -Severity 1
						Write-CMLogEntry -Value "Computer detection method set to use SystemSKU" -Severity 1
						$ComputerDetectionMethod = "SystemSKU"
					}

					# Add packages with matching criteria to list
					foreach ($Package in $BIOSPackages) {
						Write-CMLogEntry -Value "Attempting to find a match for BIOS package: $($Package.Name) ($($Package.PackageID)) $($Package.Version)" -Severity 1

						# Computer detection method matching
						$ComputerDetectionResult = $false
						switch ($ComputerManufacturer) {
							"Hewlett-Packard" {
								$PackageNameComputerModel = $Package.Name.Replace("Hewlett-Packard", "HP").Split("-").Trim()[1]
							}
							Default {
								$PackageNameComputerModel = $Package.Name.Split("-", 2).Replace($ComputerManufacturer, "").Trim()[1]
							}
						}

						switch ($ComputerDetectionMethod) {
							"ComputerModel" {
								if ($PackageNameComputerModel -like $ComputerSystemType) {
									Write-CMLogEntry -Value "Match found for computer model using detection method: $($ComputerDetectionMethod) ($($ComputerSystemType))" -Severity 1
									$ComputerDetectionResult = $true
								}
							}
							"SystemSKU" {
								# Exact-token SKU match. Previously this used -match, which treats the SKU as a
								# regex and matches substrings -- a short SKU (e.g. "20X1") could match anywhere in
								# the description, or match a package whose SKU merely contains it, producing
								# spurious multi-package matches. Tokenise both sides and compare whole
								# alphanumeric tokens instead.
								$ReportedSKUTokens = @($SystemSKU -split '[^A-Za-z0-9]+' | Where-Object { $_ })
								$PackageSKUTokens = @($Package.Description -split '[^A-Za-z0-9]+' | Where-Object { $_ })
								$SystemSKUMatched = $false
								foreach ($SKUToken in $ReportedSKUTokens) {
									if ($PackageSKUTokens -contains $SKUToken) { $SystemSKUMatched = $true; break }
								}
								if ($SystemSKUMatched) {
									Write-CMLogEntry -Value "Match found for computer model using detection method: $($ComputerDetectionMethod) ($($SystemSKU))" -Severity 1
									$ComputerDetectionResult = $true
								} else {
									Write-CMLogEntry -Value "Unable to match computer model using detection method: $($ComputerDetectionMethod) ($($SystemSKU))" -Severity 2
									if ($PackageNameComputerModel -like $ComputerSystemType) {
										Write-CMLogEntry -Value "Fallback from SystemSKU match found for computer model instead using detection method: $($ComputerDetectionMethod) ($($ComputerSystemType))" -Severity 1
										$ComputerDetectionResult = $true
									}
								}
							}
						}

						if ($ComputerDetectionResult -eq $true) {
							# Match model, manufacturer criteria
							if ($Manufacturers -contains $ComputerManufacturer) {
								if ($ComputerManufacturer -match $Package.Manufacturer) {
									Write-CMLogEntry -Value "Match found for computer model and manufacturer: $($Package.Name) ($($Package.PackageID))" -Severity 1
									$PackageList.Add($Package) | Out-Null
								} else {
									Write-CMLogEntry -Value "Package does not meet computer model and manufacturer criteria: $($Package.PackageName) ($($Package.PackageID))" -Severity 2
								}
							}
						}

					}

					# Process matching items in package list and set task sequence variable
					if ($PackageList.Count -ge 1) {
						Write-CMLogEntry -Value "[BIOSValidation]: Starting BIOS package validation phase" -Severity 1
						# Reset the flag so a stale value from an earlier task sequence step cannot force an unnecessary flash
						Set-NewBIOSAvailableFlag -Value $false
						# Determine the most current package from list
						if ($PackageList.Count -eq 1) {
							Write-CMLogEntry -Value "BIOS package list contains a single match, attempting to set task sequence variable" -Severity 1

							# Check if BIOS package is newer than currently installed
							if ($ComputerManufacturer -match "Dell") {
								Compare-BIOSVersion -AvailableBIOSVersion $PackageList[0].Version -ComputerManufacturer $ComputerManufacturer
							} elseif ($ComputerManufacturer -match "Lenovo") {
								Compare-BIOSVersion -AvailableBIOSVersion $PackageList[0].Version -AvailableBIOSReleaseDate (Get-LenovoBIOSReleaseDate -Package $PackageList[0]) -ComputerManufacturer $ComputerManufacturer
							} elseif ($ComputerManufacturer -match "Hewlett-Packard|HP") {
								Compare-BIOSVersion -AvailableBIOSVersion $PackageList[0].Version -ComputerManufacturer $ComputerManufacturer
							} elseif ($ComputerManufacturer -match "Microsoft") {
								Set-NewBIOSAvailableFlag -Value $true
							}

							if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
								# Force download re-applies the matching package even when the version already matches
								if (($TSEnvironment.Value("NewBIOSAvailable") -ne $true) -and ($Script:ForceBIOSDownload -eq $true)) {
									Write-CMLogEntry -Value "Force BIOS download enabled -- installed version already matches $($PackageList[0].Version); downloading and flagging the package for re-application (e.g. Dell recovery image recreation)" -Severity 2
									$TSEnvironment.Value("NewBIOSAvailable") = $true
								}
								if ($TSEnvironment.Value("NewBIOSAvailable") -eq $true) {
									# Attempt to download BIOS package content
									$DownloadInvocation = Invoke-CMDownloadContent -PackageID $($PackageList[0].PackageID) -DestinationLocationType Custom -DestinationVariableName "OSDBIOSPackage" -CustomLocationPath "%_SMSTSMDataPath%\BIOSPackage"
									try {
										# Check for successful package download
										if ($DownloadInvocation -eq 0) {
											Write-CMLogEntry -Value "BIOS update package content downloaded successfully. Update located in: $($TSEnvironment.Value('OSDBIOSPackage01'))" -Severity 1
											Write-CMLogEntry -Value "[BIOSPackageDownload]: Completed BIOS package download phase" -Severity 1
										} else {
											Write-CMLogEntry -Value "BIOS update package content download process returned an unhandled exit code: $($DownloadInvocation)" -Severity 3; exit 13
										}
									} catch [System.Exception] {
										Write-CMLogEntry -Value "An error occurred while downloading the BIOS update (single package match). Error message: $($_.Exception.Message)" -Severity 3; exit 14
									}
								} else {
									Write-CMLogEntry -Value "BIOS is already up to date with the latest $($PackageList[0].PackageVersion) version" -Severity 1
								}
							} else {
								if ($Script:ForceBIOSDownload -eq $true) {
									Write-CMLogEntry -Value "Task sequence engine would have been instructed to download package ID $($PackageList[0].PackageID) to %_SMSTSMDataPath%\BIOSPackage (Force BIOS download enabled)" -Severity 1
								} else {
									Write-CMLogEntry -Value "Task sequence engine would have been instructed to download package ID $($PackageList[0].PackageID) to %_SMSTSMDataPath%\BIOSPackage" -Severity 1
								}
							}

						} elseif ($PackageList.Count -ge 2) {
							Write-CMLogEntry -Value "BIOS package list contains multiple matches, attempting to set task sequence variable" -Severity 1

							# Determine the latest BIOS package by creation date
							if ($ComputerManufacturer -match "Dell") {
								$PackageList = $PackageList | Sort-Object -Property @{ Expression = { ConvertTo-PackageSourceDate -Value $_.SourceDate } } -Descending | Select-Object -First 1
							} elseif ($ComputerManufacturer -eq "Lenovo") {
								$ComputerDescription = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version
								# Preserve the full match list so the fallback can use it if the model-name filter
								# below returns nothing. The previous code re-sorted the already-nulled $PackageList,
								# so the fallback never actually recovered a package and the run bailed out with exit 1.
								$LenovoModelMatches = $PackageList
								# Attempt to find exact model match for Lenovo models which overlap model types
								$PackageList = $LenovoModelMatches | Where-object {
									($_.Name -like "*$ComputerDescription") -and ($_.Manufacturer -match $ComputerManufacturer)
								} | Sort-Object -Property @{ Expression = { ConvertTo-PackageSourceDate -Value $_.SourceDate } } -Descending | Select-Object -First 1

								If ($null -eq $PackageList) {
									# Fall back to select the latest model type match if no model name match is found
									$PackageList = $LenovoModelMatches | Sort-Object -Property @{ Expression = { ConvertTo-PackageSourceDate -Value $_.SourceDate } } -Descending | Select-Object -First 1
								}
							} elseif ($ComputerManufacturer -match "Hewlett-Packard|HP") {
								# Determine the latest BIOS package by creation date. Use SourceDate (a real
								# SMS_Package property) -- PackageCreated does not exist on the AdminService object,
								# so Sort-Object silently left the list unsorted and the "latest" selection could
								# return an older package.
								$PackageList = $PackageList | Sort-Object -Property @{ Expression = { ConvertTo-PackageSourceDate -Value $_.SourceDate } } -Descending | Select-Object -First 1

							} elseif ($ComputerManufacturer -match "Microsoft") {
								$PackageList = $PackageList | Sort-Object -Property @{ Expression = { ConvertTo-PackageSourceDate -Value $_.SourceDate } } -Descending | Select-Object -First 1
							}
							# Normalise to an array so .Count and [0] indexing behave predictably after the
							# Select-Object -First 1 reductions above collapse $PackageList to a scalar.
							$PackageList = @($PackageList | Where-Object { $null -ne $_ })
							if ($PackageList.Count -eq 1) {
								# Check if BIOS package is newer than currently installed
								if ($ComputerManufacturer -match "Dell") {
									Compare-BIOSVersion -AvailableBIOSVersion $PackageList[0].Version -ComputerManufacturer $ComputerManufacturer
								} elseif ($ComputerManufacturer -match "Lenovo") {
									Compare-BIOSVersion -AvailableBIOSVersion $PackageList[0].Version -AvailableBIOSReleaseDate (Get-LenovoBIOSReleaseDate -Package $PackageList[0]) -ComputerManufacturer $ComputerManufacturer
								} elseif ($ComputerManufacturer -match "Hewlett-Packard|HP") {
									Compare-BIOSVersion -AvailableBIOSVersion $PackageList[0].Version -ComputerManufacturer $ComputerManufacturer
								} elseif ($ComputerManufacturer -match "Microsoft") {
									Set-NewBIOSAvailableFlag -Value $true
								}

								if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
									# Force download re-applies the matching package even when the version already matches
									if (($TSEnvironment.Value("NewBIOSAvailable") -ne $true) -and ($Script:ForceBIOSDownload -eq $true)) {
										Write-CMLogEntry -Value "Force BIOS download enabled -- installed version already matches $($PackageList[0].Version); downloading and flagging the package for re-application (e.g. Dell recovery image recreation)" -Severity 2
										$TSEnvironment.Value("NewBIOSAvailable") = $true
									}
									if ($TSEnvironment.Value("NewBIOSAvailable") -eq $true) {
										$DownloadInvocation = Invoke-CMDownloadContent -PackageID $($PackageList[0].PackageID) -DestinationLocationType Custom -DestinationVariableName "OSDBIOSPackage" -CustomLocationPath "%_SMSTSMDataPath%\BIOSPackage"

										try {
											# Check for successful package download
											if ($DownloadInvocation -eq 0) {
												Write-CMLogEntry -Value "BIOS update package content downloaded successfully. Package located in: $($TSEnvironment.Value('OSDBIOSPackage01'))" -Severity 1
											} else {
												Write-CMLogEntry -Value "BIOS package content download process returned an unhandled exit code: $($DownloadInvocation)" -Severity 3; exit 13
											}
										} catch [System.Exception] {
											Write-CMLogEntry -Value "An error occurred while applying BIOS (multiple package match). Error message: $($_.Exception.Message)" -Severity 3; exit 15
										}
									} else {
										Write-CMLogEntry -Value "BIOS is already up to date with the latest $($PackageList[0].Version) version" -Severity 1
									}
								} else {
									if ($Script:ForceBIOSDownload -eq $true) {
										Write-CMLogEntry -Value "Task sequence engine would have been instructed to download package ID $($PackageList[0].PackageID) to %_SMSTSMDataPath%\BIOSPackage (Force BIOS download enabled)" -Severity 1
									} else {
										Write-CMLogEntry -Value "Task sequence engine would have been instructed to download package ID $($PackageList[0].PackageID) to %_SMSTSMDataPath%\BIOSPackage" -Severity 1
									}
								}
							} else {
								Write-CMLogEntry -Value "Unable to determine a matching BIOS package from list since an unsupported count was returned from package list, bailing out" -Severity 2; exit 1
							}
						} else {
							Write-CMLogEntry -Value "Empty BIOS package list detected, bailing out" -Severity 1
						}
					} else {
						Write-CMLogEntry -Value "BIOS package list returned from web service did not contain any objects matching the computer model and manufacturer, bailing out" -Severity 1
					}
				} else {
					Write-CMLogEntry -Value "This script is supported on Dell, Lenovo and HP systems only at this point, bailing out" -Severity 1
				}
			}
		}
	}

	Write-CMLogEntry -Value "[ApplyBIOSPackage]: Apply BIOS Package process initiated" -Severity 1
	Write-CMLogEntry -Value " - Script version: 3.0.9" -Severity 1
	if ($PSCmdLet.ParameterSetName -like "Debug") {
		Write-CMLogEntry -Value " - Apply BIOS package process initiated in debug mode" -Severity 1
	}
	Write-CMLogEntry -Value " - Apply BIOS package deployment type: $($PSCmdLet.ParameterSetName)" -Severity 1
	Write-CMLogEntry -Value " - Apply BIOS package operational mode: $($OperationalMode)" -Severity 1
	Write-CMLogEntry -Value " - Endpoint: '$($Endpoint)' | Filter: '$($Filter)'" -Severity 1

	# Determine effective BIOS force-download mode. When enabled, the matching BIOS package is
	# downloaded and flagged for flashing (NewBIOSAvailable=true) even if the installed version
	# already matches -- used to recreate Dell BIOS recovery images after OSD/SSD replacement
	# (MSEndpointMgr/ModernBIOSManagement#31). Opt-in only: the -ForceDownload switch, or the
	# SMSTSForceBIOSDownload task sequence variable ('True'/'1'/'Yes').
	$Script:ForceBIOSDownload = $false
	if ($ForceDownload.IsPresent) { $Script:ForceBIOSDownload = $true }
	if ($PSCmdLet.ParameterSetName -notlike "Debug") {
		$ForceTSValue = $TSEnvironment.Value("SMSTSForceBIOSDownload")
		if (-not [string]::IsNullOrEmpty($ForceTSValue) -and $ForceTSValue -match '^(?i:true|1|yes)$') {
			$Script:ForceBIOSDownload = $true
		}
	}
	if ($Script:ForceBIOSDownload -eq $true) {
		Write-CMLogEntry -Value " - Force BIOS download: ENABLED -- BIOS package will be downloaded even if the installed version matches" -Severity 2
	} else {
		Write-CMLogEntry -Value " - Force BIOS download: disabled (default)" -Severity 1
	}

	# Set script error preference variable
	$ErrorActionPreference = "Stop"

	try {
		Write-CMLogEntry -Value "[PrerequisiteChecker]: Starting environment prerequisite checker" -Severity 1

		# Determine the deployment type mode for BIOS package installation
		Get-DeploymentType

		# Report Secure Boot certificate posture. Intentionally evaluated before the virtual machine gate
		# below so virtual machines, which terminate script execution, are still reported on.
		Test-SecureBootCertificateStatus

		# Determine if running on supported computer system type
		Get-ComputerSystemType

		# Determine computer manufacturer, model, SystemSKU and FallbackSKU
		$ComputerData = Get-ComputerData

		# Validate required computer details have successfully been gathered from WMI
		Test-ComputerDetails -InputObject $ComputerData

		# Determine the computer detection method to be used for matching against BIOS packages
		$ComputerDetectionMethod = Set-ComputerDetectionMethod

		Write-CMLogEntry -Value "[PrerequisiteChecker]: Completed environment prerequisite checker" -Severity 1

		if ($Script:PSCmdLet.ParameterSetName -notlike "XMLPackage") {
			Write-CMLogEntry -Value "[AdminService]: Starting AdminService endpoint phase" -Severity 1

			# Detect AdminService endpoint type
			Write-CMLogEntry -Value "- Detecting AdminService endpoint type" -Severity 1
			Get-AdminServiceEndpointType

			# Determine if required values to connect to AdminService are provided
			Test-AdminServiceData

			# Determine the AdminService endpoint URL based on endpoint type
			Write-CMLogEntry -Value "- Detecting AdminService URL" -Severity 1
			Set-AdminServiceEndpointURL

			# Construct PSCredential object for AdminService authentication, this is required for both endpoint types
			Write-CMLogEntry -Value "- Constructing AdminService authentication" -Severity 1
			Get-AuthCredential

			# Attempt to retrieve an authentication token for external AdminService endpoint connectivity
			# This will only execute when the endpoint type has been detected as External, which means that authentication is needed against the Cloud Management Gateway
			if ($Script:AdminServiceEndpointType -like "External") {
				Get-AuthToken
			}

			Write-CMLogEntry -Value "[AdminService]: Completed AdminService endpoint phase" -Severity 1
		}
		Write-CMLogEntry -Value "[BIOSPackage]: Starting BIOS package retrieval using method: $($Script:PackageSource)" -Severity 1

		# Retrieve available BIOS packages from admin service
		$BIOSPackages = Get-BIOSPackages

		# Get existing BIOS version
		$CurrentBIOSVersion = (Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
		Write-CMLogEntry -Value "Current BIOS version determined as: $($CurrentBIOSVersion)" -Severity 1
		$ComputerData = $ComputerData | Select-Object -first 1

		# Determine if a newer BIOS release is available
		Get-BIOSUpdate -InputObject $ComputerData
		Write-CMLogEntry -Value "[BIOSPackage]: Completed BIOS package matching phase" -Severity 1
		Write-CMLogEntry -Value "[BIOSPackageValidation]: Completed BIOS package validation phase" -Severity 1

	} catch [System.Exception] {
		Write-CMLogEntry -Value "[BIOSPackage]: BIOS detection process failed, please refer to previous error or warning messages" -Severity 3

		# Main try-catch block was triggered, this should cause the script to fail with exit code 1
		exit 1
	}
}
End {
	if ($PSCmdLet.ParameterSetName -notlike "Debug") {
		# Reset OSDDownloadContent.exe dependant variables for further use of the task sequence step
		Invoke-CMResetDownloadContentVariables
	}

	# Write final output to log file
	Write-CMLogEntry -Value "[ApplyBIOSPackage]: Completed Apply BIOS Package process" -Severity 1
}