[CmdletBinding(DefaultParameterSetName = "BIOSUpdate")]
param ()

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot

function Assert-Equal {
	param ($Actual, $Expected, [string]$Message)
	if ($Actual -ne $Expected) {
		throw "$Message (expected '$Expected', got '$Actual')"
	}
}

function Get-CimInstance {
	[CmdletBinding()]
	param ([string]$ClassName)
	Assert-Equal $ClassName "Win32_BIOS" "BIOS comparison must query Win32_BIOS"
	if ($script:QueryFails) {
		throw "Simulated CIM query failure"
	}
	return $script:BIOS
}

function Write-CMLogEntry {
	param ([string]$Value, [int]$Severity)
	$script:LogEntries.Add($Value)
}

$OriginalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
try {
	foreach ($File in Get-ChildItem -Path $RepositoryRoot -Filter "*.ps1" -File) {
		$Tokens = $null
		$ParseErrors = $null
		$Ast = [System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$Tokens, [ref]$ParseErrors)
		Assert-Equal $ParseErrors.Count 0 "Parse errors in $($File.Name)"
		$Text = $Ast.Extent.Text
		Assert-Equal ($Text -match 'Get-WmiObject|OSVersionFallback|TargetOSVersion') $false "Stale WMI or OS-version references in $($File.Name)"
		$Commands = @($Ast.FindAll({
			param ($Node)
			$Node -is [System.Management.Automation.Language.CommandAst] -and $Node.GetCommandName() -eq "Get-CimInstance"
		}, $true))
		if ($Commands.Count -eq 0) {
			throw "No CIM queries found in $($File.Name)"
		}
		foreach ($Command in $Commands) {
			$Parameters = @($Command.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
			Assert-Equal ($Parameters -contains "ClassName") $true "CIM query missing ClassName in $($File.Name)"
		}

		if ($File.Name -notlike "Invoke-CMDownloadBIOSPackage*") {
			continue
		}

		$Definition = $Ast.Find({
			param ($Node)
			$Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq "Compare-BIOSVersion"
		}, $true)
		. ([scriptblock]::Create($Definition.Extent.Text))
		$DebugMode = $false
		$TSEnvironment = [pscustomobject]@{ Values = @{} }
		$TSEnvironment | Add-Member -MemberType ScriptMethod -Name Value -Value {
			param ($Name, $Value)
			$this.Values[$Name] = $Value
		}
		$script:BIOS = [pscustomobject]@{
			ReleaseDate = [datetime]::new(2026, 6, 29, 0, 0, 0)
			SMBIOSBIOSVersion = "1.2.3"
			SystemBiosMajorVersion = 1
			SystemBiosMinorVersion = 2
		}
		$script:QueryFails = $false
		foreach ($CultureName in @("en-US", "ar-SA")) {
			[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($CultureName)
			foreach ($Case in @(
				@{ Date = "20260630"; Expected = $true },
				@{ Date = "20260629"; Expected = $false },
				@{ Date = "20260628"; Expected = $false }
			)) {
				$TSEnvironment.Values.Clear()
				$script:LogEntries = [System.Collections.Generic.List[string]]::new()
				Compare-BIOSVersion -ComputerManufacturer "Lenovo" -AvailableBIOSReleaseDate $Case.Date
				Assert-Equal ($TSEnvironment.Values["NewBIOSAvailable"] -eq $true) $Case.Expected "Lenovo comparison in $($File.Name), $CultureName, $($Case.Date)"
				Assert-Equal ($script:LogEntries -contains "Current BIOS release date detected as 20260629.") $true "Lenovo date must retain Gregorian yyyyMMdd format"
			}
		}

		foreach ($Case in @(
			@{ Manufacturer = "Dell"; Version = "1.2.4"; Expected = $true },
			@{ Manufacturer = "Dell"; Version = "1.2.3"; Expected = $false },
			@{ Manufacturer = "Hewlett-Packard"; Version = "1.3"; Expected = $true },
			@{ Manufacturer = "Hewlett-Packard"; Version = "1.2"; Expected = $false }
		)) {
			$TSEnvironment.Values.Clear()
			Compare-BIOSVersion -ComputerManufacturer $Case.Manufacturer -AvailableBIOSVersion $Case.Version
			Assert-Equal ($TSEnvironment.Values["NewBIOSAvailable"] -eq $true) $Case.Expected "Version comparison in $($File.Name), $($Case.Manufacturer), $($Case.Version)"
		}

		foreach ($Case in @(
			@{ Current = "A9"; Available = "A10"; Expected = $true },
			@{ Current = "A10"; Available = "A9"; Expected = $false },
			@{ Current = "A10"; Available = "A10"; Expected = $false }
		)) {
			$script:BIOS.SMBIOSBIOSVersion = $Case.Current
			$TSEnvironment.Values.Clear()
			Compare-BIOSVersion -ComputerManufacturer "Dell" `
				-AvailableBIOSVersion $Case.Available
			Assert-Equal ($TSEnvironment.Values["NewBIOSAvailable"] -eq $true) `
				$Case.Expected "Dell A-revision comparison in $($File.Name), $($Case.Current) to $($Case.Available)"
		}
		$script:BIOS.SMBIOSBIOSVersion = "1.2.3"

		$script:QueryFails = $true
		$Failure = $null
		try {
			Compare-BIOSVersion -ComputerManufacturer "Lenovo" -AvailableBIOSReleaseDate "20260630"
		} catch {
			$Failure = $_.Exception.Message
		}
		Assert-Equal $Failure "Simulated CIM query failure" "CIM failure must not be silently ignored"
	}
	Write-Output "CIM migration regression checks passed."
} finally {
	[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
}
