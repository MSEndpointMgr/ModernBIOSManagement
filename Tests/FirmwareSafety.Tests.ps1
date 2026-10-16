[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "", Justification = "This standalone regression harness uses a fixed synthetic test password only to construct an in-memory PSCredential.")]
[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot

function Assert-Equal {
	param ($Actual, $Expected, [string]$Message)
	if ($Actual -ne $Expected) {
		throw "$Message (expected '$Expected', got '$Actual')"
	}
}

function Get-FunctionDefinition {
	param ([string]$ScriptPath, [string]$Name)

	$Tokens = $null
	$ParseErrors = $null
	$Ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$Tokens, [ref]$ParseErrors)
	Assert-Equal $ParseErrors.Count 0 "$([System.IO.Path]::GetFileName($ScriptPath)) must parse"
	$Definition = $Ast.Find({
		param ($Node)
		$Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $Name
	}, $true)
	if ($null -eq $Definition) {
		throw "$Name was not found in $ScriptPath"
	}
	return $Definition.Extent.Text
}

function Write-CMLogEntry {
	param ([string]$Value, [string]$Severity)
	$script:LogEntries.Add([pscustomobject]@{ Value = $Value; Severity = $Severity })
}

$DellScriptPath = Join-Path $RepositoryRoot "Invoke-DellBIOSUpdate.ps1"
. ([scriptblock]::Create((Get-FunctionDefinition -ScriptPath $DellScriptPath -Name "Resolve-DellBIOSUpdateExitCode")))

$TSEnvironment = [pscustomobject]@{ Values = @{} }
$TSEnvironment | Add-Member -MemberType ScriptMethod -Name Value -Value {
	param ($Name, $Value)
	$this.Values[$Name] = $Value
}

foreach ($Case in @(
	@{ Code = 0; Result = 0; Reboot = $false; ColdBoot = $false },
	@{ Code = 2; Result = 0; Reboot = $true; ColdBoot = $false },
	@{ Code = 3; Result = 0; Reboot = $false; ColdBoot = $false },
	@{ Code = 6; Result = 0; Reboot = $false; ColdBoot = $false },
	@{ Code = 13; Result = 0; Reboot = $false; ColdBoot = $false },
	@{ Code = 14; Result = 0; Reboot = $true; ColdBoot = $false },
	@{ Code = 15; Result = 0; Reboot = $false; ColdBoot = $true },
	@{ Code = 16; Result = 0; Reboot = $false; ColdBoot = $true },
	@{ Code = 17; Result = 0; Reboot = $false; ColdBoot = $false },
	@{ Code = 18; Result = 0; Reboot = $false; ColdBoot = $false },
	@{ Code = 19; Result = 0; Reboot = $false; ColdBoot = $true },
	@{ Code = 20; Result = 0; Reboot = $false; ColdBoot = $false },
	@{ Code = 1; Result = 1; Reboot = $false; ColdBoot = $false },
	@{ Code = 4; Result = 4; Reboot = $false; ColdBoot = $false },
	@{ Code = 5; Result = 5; Reboot = $false; ColdBoot = $false },
	@{ Code = 9; Result = 9; Reboot = $false; ColdBoot = $false },
	@{ Code = 10; Result = 10; Reboot = $false; ColdBoot = $false },
	@{ Code = 42; Result = 42; Reboot = $false; ColdBoot = $false }
)) {
	$TSEnvironment.Values.Clear()
	$script:LogEntries = [System.Collections.Generic.List[object]]::new()
	$ActualResult = Resolve-DellBIOSUpdateExitCode -ExitCode $Case.Code -BIOSLogFile "Dell.log" -Phase "OS online"
	Assert-Equal $ActualResult $Case.Result "Dell exit code $($Case.Code) result"
	Assert-Equal $TSEnvironment.Values.ContainsKey("SMSTSBIOSUpdateRebootRequired") $Case.Reboot "Dell exit code $($Case.Code) reboot flag"
	Assert-Equal $TSEnvironment.Values.ContainsKey("SMSTSBIOSUpdateColdBootRequired") $Case.ColdBoot "Dell exit code $($Case.Code) cold-boot flag"
	Assert-Equal ($script:LogEntries.Count -gt 0) $true "Dell exit code $($Case.Code) must be logged"

	$TSEnvironment.Values.Clear()
	$null = Resolve-DellBIOSUpdateExitCode -ExitCode $Case.Code -BIOSLogFile "Dell.log" -Phase "OS offline" -WinPE $true
	Assert-Equal $TSEnvironment.Values.ContainsKey("SMSTSBIOSInOSUpdateRequired") ($Case.Result -eq 0) "Dell exit code $($Case.Code) WinPE completion flag"
}

$DownloaderPath = Join-Path $RepositoryRoot "Invoke-CMDownloadBIOSPackage.ps1"
. ([scriptblock]::Create((Get-FunctionDefinition -ScriptPath $DownloaderPath -Name "Test-VirtualMachinePlatform")))

foreach ($Case in @(
	@{ Model = "Virtual Machine"; Manufacturer = "Microsoft Corporation"; Expected = $true },
	@{ Model = "VMware Virtual Platform None"; Manufacturer = "VMware, Inc."; Expected = $true },
	@{ Model = "m7i.large"; Manufacturer = "Amazon EC2"; Expected = $true },
	@{ Model = "OpenStack Nova"; Manufacturer = "OpenStack Foundation"; Expected = $true },
	@{ Model = "Surface Laptop 7"; Manufacturer = "Microsoft Corporation"; Expected = $false },
	@{ Model = "Latitude 7450"; Manufacturer = "Dell Inc."; Expected = $false }
)) {
	Assert-Equal (Test-VirtualMachinePlatform -Model $Case.Model -Manufacturer $Case.Manufacturer) $Case.Expected "VM detection for $($Case.Manufacturer) $($Case.Model)"
}

$RequiredVendorTokens = @("VMware Virtual Platform None", "Google", "Amazon EC2", "OpenStack")
foreach ($FileName in @("Invoke-DellBIOSUpdate.ps1", "Invoke-HPBIOSUpdate.ps1", "Invoke-LenovoBIOSUpdate.ps1", "Invoke-MicrosoftBIOSUpdate.ps1")) {
	$Text = Get-Content -LiteralPath (Join-Path $RepositoryRoot $FileName) -Raw
	foreach ($Token in $RequiredVendorTokens) {
		Assert-Equal $Text.Contains($Token) $true "$FileName VM classifier must include $Token"
	}
	Assert-Equal $Text.Contains('@(Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop)') $true "$FileName must normalize platform inventory results"
	Assert-Equal $Text.Contains('$ComputerSystems.Count -ne 1') $true "$FileName must reject missing or ambiguous platform inventory"
	Assert-Equal $Text.Contains('[string]::IsNullOrWhiteSpace([string]$ComputerSystems[0].Model)') $true "$FileName must reject an empty platform model"
	Assert-Equal $Text.Contains('[string]::IsNullOrWhiteSpace([string]$ComputerSystems[0].Manufacturer)') $true "$FileName must reject an empty platform manufacturer"
}

foreach ($FileName in @("Invoke-HPBIOSUpdate.ps1", "Invoke-LenovoBIOSUpdate.ps1", "Invoke-MicrosoftBIOSUpdate.ps1")) {
	$Text = Get-Content -LiteralPath (Join-Path $RepositoryRoot $FileName) -Raw
	Assert-Equal $Text.Contains('SMSTSBIOSUpdateRebootRequired') $true "$FileName must report reboot-required success"
}

$LegacyText = Get-Content -LiteralPath (Join-Path $RepositoryRoot "Invoke-CMDownloadBIOSPackage_Legacy.ps1") -Raw
Assert-Equal $LegacyText.Contains("VMware Virtual Platform None") $true "Legacy downloader VM model list"
Assert-Equal $LegacyText.Contains('$PackageList = @($PackageList | Where-Object { $null -ne $_ })') $true "Legacy downloader must normalize the reduced package list before checking Count"

$DownloaderText = Get-Content -LiteralPath $DownloaderPath -Raw
foreach ($Text in @($DownloaderText, $LegacyText)) {
	Assert-Equal ($Text -match "ServerCertificateValidationCallback|Set-CertificateValidationCallback") $false "Downloaders must not bypass HTTPS certificate validation"
}
Assert-Equal ($DownloaderText -match "(?i)\b(Install|Update)-Module\b") $false "Downloader must not install gallery modules at runtime"
Assert-Equal ($DownloaderText.Contains("Install-AuthModule")) $false "Legacy authentication module bootstrap must be absent"
Assert-Equal ($DownloaderText.Contains('throw "Unable to construct Microsoft.SMS.TSEnvironment object.')) $true "Task-sequence initialization must fail closed"

. ([scriptblock]::Create((Get-FunctionDefinition -ScriptPath $DownloaderPath -Name "Get-AuthToken")))
function Invoke-RestMethod {
	param($Method, $Uri, $Body, $ContentType, $ErrorAction)
	$script:TokenRequest = [pscustomobject]@{
		Method = $Method
		Uri = $Uri
		Body = $Body.Clone()
		ContentType = $ContentType
	}
	[pscustomobject]@{ token_type = "Bearer"; access_token = "test-token" }
}
$TenantName = "contoso.onmicrosoft.com"
$ClientID = "00000000-0000-0000-0000-000000000001"
$ApplicationIDURI = "https://ConfigMgrService"
$Script:Password = "P@ssw0rd!"
$Credential = New-Object System.Management.Automation.PSCredential(
	"svc-bios@contoso.com",
	(ConvertTo-SecureString $Script:Password -AsPlainText -Force))
Get-AuthToken
Assert-Equal $script:TokenRequest.Uri "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/token" "Direct OAuth endpoint"
Assert-Equal $script:TokenRequest.Method "Post" "Direct OAuth method"
Assert-Equal $script:TokenRequest.ContentType "application/x-www-form-urlencoded" "Direct OAuth content type"
Assert-Equal $script:TokenRequest.Body.username "svc-bios@contoso.com" "Direct OAuth user name"
Assert-Equal $script:TokenRequest.Body.password "P@ssw0rd!" "Direct OAuth password"
Assert-Equal $Script:AuthToken.Authorization "Bearer test-token" "Direct OAuth authorization header"
Assert-Equal ($null -eq $Script:Password) $true "Plain-text password is cleared"
Assert-Equal ($null -eq $Script:Credential) $true "Credential is cleared"

foreach ($FileName in @("Invoke-DellBIOSUpdate.ps1", "Invoke-HPBIOSUpdate.ps1", "Invoke-LenovoBIOSUpdate.ps1")) {
	$Text = Get-Content -LiteralPath (Join-Path $RepositoryRoot $FileName) -Raw
	Assert-Equal $Text.Contains("Manage-Bde -Protectors -Disable `$env:SystemDrive -RebootCount 1") $true "$FileName must bound BitLocker suspension to one reboot"
	Assert-Equal $Text.Contains("Manage-Bde -Protectors -Enable `$env:SystemDrive") $true "$FileName must restore BitLocker on failure or no-reboot success"
	Assert-Equal $Text.Contains('$LogsDirectory = Join-Path -Path $env:SystemRoot -ChildPath "Temp"') $true "$FileName must support logging without a task-sequence object"
	Assert-Equal $Text.Contains('ProtectionStatus -notin @(0, 1)') $true "$FileName must reject unknown BitLocker protection states"
	Assert-Equal ($Text -match '\.(Count) -ne 1') $true "$FileName must require exactly one operating-system BitLocker volume"
}

$DellText = Get-Content -LiteralPath $DellScriptPath -Raw
Assert-Equal $DellText.Contains('-replace [regex]::Escape($Password)') $true "Dell password masking must escape regular-expression characters"

$LenovoText = Get-Content -LiteralPath (Join-Path $RepositoryRoot "Invoke-LenovoBIOSUpdate.ps1") -Raw
Assert-Equal $LenovoText.Contains("undocumented exit code") $true "Lenovo undocumented result must not be reported as success"
Assert-Equal $LenovoText.Contains('-replace [regex]::Escape($Password)') $true "Lenovo password masking must escape regular-expression characters"

Write-Output "Firmware safety regression checks passed."
