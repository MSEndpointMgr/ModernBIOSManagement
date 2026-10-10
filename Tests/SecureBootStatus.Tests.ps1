[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$ScriptPath = Join-Path $RepositoryRoot "Invoke-CMDownloadBIOSPackage.ps1"

function Assert-Equal {
	param ($Actual, $Expected, [string]$Message)
	if ($Actual -ne $Expected) {
		throw "$Message (expected '$Expected', got '$Actual')"
	}
}

$Tokens = $null
$ParseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$Tokens, [ref]$ParseErrors)
Assert-Equal $ParseErrors.Count 0 "Downloader must parse before Secure Boot tests run"
$Definition = $Ast.Find({
	param ($Node)
	$Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq "Test-SecureBootCertificateStatus"
}, $true)
if ($null -eq $Definition) {
	throw "Test-SecureBootCertificateStatus was not found"
}
. ([scriptblock]::Create($Definition.Extent.Text))

function Write-CMLogEntry {
	param ([string]$Value, [int]$Severity)
	$script:LogEntries.Add([pscustomobject]@{ Value = $Value; Severity = $Severity })
}

function Get-Command {
	param ([string]$Name, [System.Management.Automation.ActionPreference]$ErrorAction)
	if ($script:Scenario -eq "Unavailable") {
		return $null
	}
	return [pscustomobject]@{ Name = $Name }
}

function Confirm-SecureBootUEFI {
	param ([System.Management.Automation.ActionPreference]$ErrorAction)
	if ($script:Scenario -eq "Error") {
		throw "Simulated Secure Boot failure"
	}
	return ($script:Scenario -ne "Disabled")
}

function Get-SecureBootUEFI {
	param ([string]$Name, [System.Management.Automation.ActionPreference]$ErrorAction)
	Assert-Equal $Name "db" "Secure Boot detection must inspect DB"
	$Text = if ($script:Scenario -in @("Present", "Updated")) { "Windows UEFI CA 2023" } else { "Microsoft Windows Production PCA 2011" }
	return [pscustomobject]@{ Bytes = [System.Text.Encoding]::ASCII.GetBytes($Text) }
}

function Get-ItemProperty {
	param ([string]$LiteralPath, [string]$Name, [System.Management.Automation.ActionPreference]$ErrorAction)
	Assert-Equal $LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" "Servicing status registry path"
	Assert-Equal $Name "UEFICA2023Status" "Servicing status registry value"
	if ($script:Scenario -eq "Updated") {
		return [pscustomobject]@{ UEFICA2023Status = "Updated" }
	}
	return $null
}

$TSEnvironment = [pscustomobject]@{ Values = @{} }
$TSEnvironment | Add-Member -MemberType ScriptMethod -Name Value -Value {
	param ($Name, $Value)
	$this.Values[$Name] = $Value
}

foreach ($Case in @(
	@{ Scenario = "Unavailable"; Present = $false; Status = "Unavailable" },
	@{ Scenario = "Disabled"; Present = $false; Status = "Disabled" },
	@{ Scenario = "NotPresent"; Present = $false; Status = "NotPresent" },
	@{ Scenario = "Present"; Present = $true; Status = "Present" },
	@{ Scenario = "Updated"; Present = $true; Status = "Updated" },
	@{ Scenario = "Error"; Present = $false; Status = "Error" }
)) {
	$script:Scenario = $Case.Scenario
	$script:LogEntries = [System.Collections.Generic.List[object]]::new()
	$TSEnvironment.Values.Clear()
	Test-SecureBootCertificateStatus
	Assert-Equal $TSEnvironment.Values["SecureBootCertificate2023Present"] $Case.Present "$($Case.Scenario) presence result"
	Assert-Equal $TSEnvironment.Values["SecureBootCertificate2023Status"] $Case.Status "$($Case.Scenario) status result"
}

Write-Output "Secure Boot status regression checks passed."
