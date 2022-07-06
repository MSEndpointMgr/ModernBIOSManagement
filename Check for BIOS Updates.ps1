# Attempts to construst TSEnvironment object
# Load Microsoft.SMS.TSEnvironment COM object
try {
    $TSEnvironment = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Continue
}
catch [System.Exception] {
    #Write-CMLogEntry -Value "Not in a TSEnvironment, we must be testing from Windows" -Severity 1
}

#Provides logging in CMTrace style (from sccconfigmgr.com)
if ($TSEnvironment) {
    $LogsDirectory = $Script:TSEnvironment.Value("_SMSTSLogPath")

}
else {
    $LogsDirectory = Join-Path $env:SystemRoot "Temp"

}
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
        [string]$FileName = "BIOS Maintenance.log"
    )
    # Determine log file location
    $LogFilePath = Join-Path -Path $LogsDirectory -ChildPath $FileName
	
    # Construct time stamp for log entry
    if (-not (Test-Path -Path 'variable:global:TimezoneBias')) {
        [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
        if ($TimezoneBias -match "^-") {
            $TimezoneBias = $TimezoneBias.Replace('-', '+')
        }
        else {
            $TimezoneBias = '-' + $TimezoneBias
        }
    }
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
	
    # Construct date for log entry
    $Date = (Get-Date -Format "MM-dd-yyyy")
	
    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	
    # Construct final log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""BIOS_Maintenance"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
	
    # Add value to log file
    try {
		
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to append log entry to $FileName. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
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
        $CurrentBIOSVersion = (Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
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
        }
        elseif ($CurrentBIOSVersion -like "A*") {
            # Compare current BIOS release to available
            if ($AvailableBIOSVersion -like "*.*.*") {
                # Assume that the bios is new as moving from Axx to x.x.x formats
                # Write output to task sequence variable
                if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
                    $TSEnvironment.Value("NewBIOSAvailable") = $true
                }
                Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
            }
            elseif ($AvailableBIOSVersion -gt $CurrentBIOSVersion) {
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
        $CurrentBIOSReleaseDate = ((Get-WmiObject -Class Win32_BIOS | Select-Object -Property *).ReleaseDate).SubString(0, 8)
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
        $CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
		
        # Update version formatting
        $AvailableBIOSVersion = $AvailableBIOSVersion.TrimEnd(".")
        $AvailableBIOSVersion = $AvailableBIOSVersion.Split(" ")[0]
		
        # Detect new versus old BIOS formats
        switch -wildcard ($($CurrentBIOSProperties.SMBIOSBIOSVersion)) {
            "*ver*" {
                if ($CurrentBIOSProperties.SMBIOSBIOSVersion -match '.F.\d+$') {
                    $CurrentBIOSVersion = ($CurrentBIOSProperties.SMBIOSBIOSVersion -split "Ver.")[1].Trim()
                    $BIOSVersionParseable = $false
                }
                else {
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


# Instantiates connection to ASD-Webservice using API key
$URI = $TSEnvironment.Value("ASDWebServiceURI").Replace('/osd', '')
$SecretKey = $TSEnvironment.Value("ASDWebServiceKey")
Write-CMLogEntry -Value "[INFO] URI retrieved: $URI" -Severity 1

# $Manufacturer = $WMIObjectWin32Computer.Manufacturer
$WMIObjectWin32Computer = (Get-WmiObject -Class Win32_ComputerSystem)

$Manufacturer = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()
switch -Wildcard ($Manufacturer) {
    "*Microsoft*" {
        $Manufacturer = "Microsoft"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
    }
    "*HP*" {
        $Manufacturer = "HP"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
        $CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
        $BIOSVersionProperty = 'Version'
    }
    "*Hewlett-Packard*" {
        $Manufacturer = "Hewlett-Packard"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
        $CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
        $BIOSVersionProperty = 'Version'
    }
    "*Dell*" {
        $Manufacturer = "Dell"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
        $CurrentBIOSVersion = (Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
        $BIOSVersionProperty = 'Version'
    }
    "*Lenovo*" {
        $Manufacturer = "Lenovo"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystemProduct" | Select-Object -ExpandProperty Version).Trim()
        $CurrentBIOSVersion = ((Get-WmiObject -Class Win32_BIOS | Select-Object -Property *).ReleaseDate).SubString(0, 8)
        $BIOSVersionProperty = 'Description'
    }
    "*Panasonic*" {
        $Manufacturer = "Panasonic Corporation"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
    }
    "*Viglen*" {
        $Manufacturer = "Viglen"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
    }
    "*AZW*" {
        $Manufacturer = "AZW"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
    }
    "*Fujitsu*" {
        $Manufacturer = "Fujitsu"
        $Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
    }
    default {
        $Manufacturer = $WMIObjectWin32Computer.Manufacturer
        $Model = $WMIObjectWin32Computer.Model
    }
}

# Detect new versus old BIOS formats
if ($Manufacturer -match "Hewlett-Packard|HP") {
    switch -wildcard ($($CurrentBIOSProperties.SMBIOSBIOSVersion)) {
        "*ver*" {
            if ($CurrentBIOSProperties.SMBIOSBIOSVersion -match '.F.\d+$') {
                $CurrentBIOSVersion = ($CurrentBIOSProperties.SMBIOSBIOSVersion -split "Ver.")[1].Trim()
                $BIOSVersionParseable = $false
            }
            else {
                $CurrentBIOSVersion = [System.Version]::Parse(($CurrentBIOSProperties.SMBIOSBIOSVersion).TrimStart($CurrentBIOSProperties.SMBIOSBIOSVersion.Split(".")[0]).TrimStart(".").Trim().Split(" ")[0])
                $BIOSVersionParseable = $true
            }
        }
        default {
            $CurrentBIOSVersion = "$($CurrentBIOSProperties.SystemBiosMajorVersion).$($CurrentBIOSProperties.SystemBiosMinorVersion)"
            $BIOSVersionParseable = $true
        }
    }
}


$APICallParams = @{
    Headers     = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $($SecretKey)"
    }
    Method      = 'GET'
    URI         = "$URI/reports/Get-CMBIOSPackage?Model=$Model"
    ErrorAction = "SilentlyContinue"
}

Write-CMLogEntry -Value "[INFO] Calling API for BIOS package information: $APICallParams with model $Model" -Severity 1
$APIResults = (Invoke-RestMethod @APICallParams)
$AvailableBIOSVersion = $APIResults.$BIOSVersionProperty

switch ($BIOSVersionProperty) {
    'Description' {
        $AvailableBIOSVersion = $AvailableBIOSVersion.Split(':')[2].Split(')')[0]
        Compare-BIOSVersion -AvailableBIOSReleaseDate $AvailableBIOSVersion -ComputerManufacturer $Manufacturer
    }
    'Version' {
        Compare-BIOSVersion -AvailableBIOSVersion $AvailableBIOSVersion -ComputerManufacturer $Manufacturer
    }
}

if ($APIResults.Description -match '=')
{
    Write-CMLogEntry -Value "[INFO] Special BIOS detected. Checking for conditions (Phase or prereq)" -Severity 1
    $Object = $APIResults.Description.Split(")")
    $Object | ForEach-Object 
    {
        switch -Wildcard ($PSItem) 
        {
            "*Phase"
            {
                $Phase = $PSItem.Split('=')[1]
                $TSEnvironment.Value("BIOSPhase") = $Phase
                Write-CMLogEntry -Value "[INFO] Special BIOS detected. Must run in $Phase" -Severity 1
            }
            "*PreReq"
            {
                $PreReq = $PSItem.Split('=')[1]
                $TSEnvironment.Value("BIOSPreReq") = $PreReq
                Write-CMLogEntry -Value "[INFO] Special BIOS detected. PreReq Version detected $PreReq" -Severity 1
            }
        }
    }
}

Write-CMLogEntry -Value "[INFO] API call results: $AvailableBIOSVersion" -Severity 1