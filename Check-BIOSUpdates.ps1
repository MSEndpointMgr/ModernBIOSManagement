<#
.SYNOPSIS
	Compare current and available BIOS version from custom webservice

.DESCRIPTION
    This script will determine the model of the computer and manufacturer and then query a custom API for available BIOS update packages.
    It will then determine if the available version is newer than what is installed.
    

.EXAMPLE
	.\


.NOTES
    FileName:    Check for BIOS Updates.ps1
	Author:      Stuart Adams
    
#>
[CmdletBinding()]
param (
    [parameter(Mandatory = $false, ParameterSetName = "Debug", HelpMessage = "Set the script to operate in 'DebugMode' deployment type mode.")]
    [switch]$DebugMode,

    [parameter(Mandatory = $false, ParameterSetName = "Debug", HelpMessage = "When using debug mode, specifiy the URI.")]
    [string]$URI,

    [parameter(Mandatory = $false, ParameterSetName = "Debug", HelpMessage = "When using debug mode, specifiy the secret key.")]
    [string]$SecretKey,

    [parameter(Mandatory = $false, ParameterSetName = "Debug", HelpMessage = "When using debug mode, specifiy the secret key.")]
    [switch]$ImitateModel
)

begin {
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
}

process {
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
            Write-CMLogEntry -Value "Available BIOS release detected as $($AvailableBIOSVersion)." -Severity 1

            # Determine Dell BIOS revision format
            if ($CurrentBIOSVersion -like "*.*.*") {
                # Compare current BIOS release to available
                if ([System.Version]$AvailableBIOSVersion -gt [System.Version]$CurrentBIOSVersion) {
                    # Write output to task sequence variable
                    if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
                        $TSEnvironment.Value("NewBIOSAvailable") = $true
                        $TSEnvironment.Value("AvailableBIOSVersion") = $AvailableBIOSVersion
                        $TSEnvironment.Value("CurrentBIOSVersion") = $CurrentBIOSVersion
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
                        $TSEnvironment.Value("AvailableBIOSVersion") = $AvailableBIOSVersion
                        $TSEnvironment.Value("CurrentBIOSVersion") = $CurrentBIOSVersion
                    }
                    Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
                }
                elseif ($AvailableBIOSVersion -gt $CurrentBIOSVersion) {
                    # Write output to task sequence variable
                    if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
                        $TSEnvironment.Value("NewBIOSAvailable") = $true
                        $TSEnvironment.Value("AvailableBIOSVersion") = $AvailableBIOSVersion
                        $TSEnvironment.Value("CurrentBIOSVersion") = $CurrentBIOSVersion
                    }
                    Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
                }
            }
        }

        if ($ComputerManufacturer -match "Lenovo") {
            if ($AvailableBIOSReleaseDate) {
                # Obtain current BIOS release
                $CurrentBIOSReleaseDate = ((Get-WmiObject -Class Win32_BIOS | Select-Object -Property *).ReleaseDate).SubString(0, 8)
                Write-CMLogEntry -Value "Current BIOS release date detected as $($CurrentBIOSReleaseDate)." -Severity 1
                Write-CMLogEntry -Value "Available BIOS release date detected as $($AvailableBIOSReleaseDate)." -Severity 1

                # Compare current BIOS release to available
                if ($AvailableBIOSReleaseDate -gt $CurrentBIOSReleaseDate) {
                    # Write output to task sequence variable
                    if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
                        $TSEnvironment.Value("NewBIOSAvailable") = $true
                        $TSEnvironment.Value("AvailableBIOSVersion") = $AvailableBIOSReleaseDate
                        $TSEnvironment.Value("CurrentBIOSVersion") = $CurrentBIOSReleaseDate
                    }
                    Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current date release dated $($CurrentBIOSReleaseDate) will be replaced by release $($AvailableBIOSReleaseDate)." -Severity 1
                }
            } else {
                # Obtain current BIOS release
                $CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
                
                $CurrentBIOSVersion = $CurrentBIOSProperties.Name

                if ($CurrentBIOSVersion.ToCharArray() -contains '('){
                    $CurrentBIOSVersion = $CurrentBIOSVersion.Split('(')[1].Split(')')[0]
                    $CurrentBIOSVersion = $CurrentBIOSVersion.Trim(' ')
                    $CurrentBIOSVersion = [System.Version]::Parse($CurrentBIOSVersion)
                    $BIOSVersionParseable = $true
                    Write-CMLogEntry -Value "Current BIOS version detected as $($CurrentBIOSVersion) (Extracted from $($CurrentBIOSProperties.Name)." -Severity 1
                } else {
                    $BIOSVersionParseable = $false
                    Write-CMLogEntry -Value "Current BIOS version detected as $($CurrentBIOSVersion) - Need to extrapolate version details to compare." -Severity 1
                }
                
                # Compare current BIOS release to available
                switch ($BIOSVersionParseable) {
                    $true {
                        if ([System.Version]$AvailableBIOSVersion -gt [System.Version]$CurrentBIOSVersion) {
                            # Write output to task sequence variable
                            if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
                                $TSEnvironment.Value("NewBIOSAvailable") = $true
                                $TSEnvironment.Value("AvailableBIOSVersion") = $AvailableBIOSVersion
                                $TSEnvironment.Value("CurrentBIOSVersion") = $CurrentBIOSVersion
                            }
                            Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
                        }
                    }
                    $false {
                        $AvailableBIOSVersion = Convert-LenovoBIOSVersionName -BIOSVersionInfo $AvailableBIOSVersion
                        $CurrentBIOSVersion = Convert-LenovoBIOSVersionName -BIOSVersionInfo $CurrentBIOSVersion
                        Write-CMLogEntry -Value "Comparing new BIOS version $AvailableBIOSVersion to current version $CurrentBIOSVersion" -Severity 1
                        if ($AvailableBIOSVersion -gt $CurrentBIOSVersion) {
                            # Write output to task sequence variable
                            if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
                                $TSEnvironment.Value("NewBIOSAvailable") = $true
                                $TSEnvironment.Value("AvailableBIOSVersion") = $AvailableBIOSVersion
                                $TSEnvironment.Value("CurrentBIOSVersion") = $CurrentBIOSVersion
                            }
                            Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
                        }
                    }
                }
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
                            $TSEnvironment.Value("AvailableBIOSVersion") = $AvailableBIOSVersion
                            $TSEnvironment.Value("CurrentBIOSVersion") = $CurrentBIOSVersion
                        }
                        Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
                    }
                }
                $false {
                    if ([System.Int32]::Parse($AvailableBIOSVersion.TrimStart("F.")) -gt [System.Int32]::Parse($CurrentBIOSVersion.TrimStart("F."))) {
                        # Write output to task sequence variable
                        if ($Script:PSCmdlet.ParameterSetName -notlike "Debug") {
                            $TSEnvironment.Value("NewBIOSAvailable") = $true
                            $TSEnvironment.Value("AvailableBIOSVersion") = $AvailableBIOSVersion
                            $TSEnvironment.Value("CurrentBIOSVersion") = $CurrentBIOSVersion
                        }
                        Write-CMLogEntry -Value "A new version of the BIOS has been detected. Current release $($CurrentBIOSVersion) will be replaced by $($AvailableBIOSVersion)." -Severity 1
                    }
                }
            }
        }
    }

    function Convert-LenovoBIOSVersionName {
        param (
            [parameter(Mandatory = $true, HelpMessage = "BIOS version info in string format")]
            [ValidateNotNullOrEmpty()]
            [string]$BIOSVersionInfo
        )
        
        $BIOSPlatform = $BIOSVersionInfo.SubString(0,3) # First three characters are platform ID
        $BIOSVersion = $BIOSVersionInfo.SubString($BIOSVersionInfo.Length -3, 3).Substring(0,2) # Two charactars before the last are version number in hex
        Write-CMLogEntry -Value "Returning Lenovo BIOS version value. BIOS Platform: $BIOSPlatform BIOS Version: $BIOSVersion" -Severity 1

        return $BIOSVersion
    }

    function Get-ComputerData {
        # Create a custom object for computer details gathered from local WMI
        $ComputerDetails = [PSCustomObject]@{
            Manufacturer        = $null
            Model               = $null
            SystemSKU           = $null
            FallbackSKU         = $null
            BIOSVersionProperty = $null
        }

        # Gather computer details based upon specific computer manufacturer
        $ComputerManufacturer = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()
        switch -Wildcard ($ComputerManufacturer) {
            "*Microsoft*" {
                $ComputerDetails.Manufacturer = "Microsoft"
                $ComputerDetails.Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
                $ComputerDetails.SystemSKU = Get-WmiObject -Namespace "root\wmi" -Class "MS_SystemInformation" | Select-Object -ExpandProperty SystemSKU
                $ComputerDetails.BIOSVersionProperty = 'Version'
            }
            "*HP*" {
                $ComputerDetails.Manufacturer = "HP"
                $ComputerDetails.Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
                $ComputerDetails.SystemSKU = (Get-CimInstance -ClassName "MS_SystemInformation" -Namespace "root\WMI").BaseBoardProduct.Trim()
                $ComputerDetails.BIOSVersionProperty = 'Version'
            }
            "*Hewlett-Packard*" {
                $ComputerDetails.Manufacturer = "HP"
                $ComputerDetails.Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
                $ComputerDetails.SystemSKU = (Get-CimInstance -ClassName "MS_SystemInformation" -Namespace "root\WMI").BaseBoardProduct.Trim()
                $ComputerDetails.BIOSVersionProperty = 'Version'
            }
            "*Dell*" {
                $ComputerDetails.Manufacturer = "Dell"
                $ComputerDetails.Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
                $ComputerDetails.SystemSKU = (Get-CimInstance -ClassName "MS_SystemInformation" -Namespace "root\WMI").SystemSku.Trim()
                [string]$OEMString = Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty OEMStringArray
                if (!($OEMString -eq 'www.dell.com')) {
                    $ComputerDetails.FallbackSKU = [regex]::Matches($OEMString, '\[\S*]')[0].Value.TrimStart("[").TrimEnd("]")
                }
                $ComputerDetails.BIOSVersionProperty = 'Version'
            }
            "*Lenovo*" {
                $ComputerDetails.Manufacturer = "Lenovo"
                $ComputerDetails.Model = (Get-WmiObject -Class "Win32_ComputerSystemProduct" | Select-Object -ExpandProperty Version).Trim()
                $ComputerDetails.SystemSKU = ((Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).SubString(0, 4)).Trim()
                $ComputerDetails.BIOSVersionProperty = 'Version' #'Description'
            }
            "*Panasonic*" {
                $ComputerDetails.Manufacturer = "Panasonic Corporation"
                $ComputerDetails.Model = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Model).Trim()
                $ComputerDetails.SystemSKU = (Get-CimInstance -ClassName "MS_SystemInformation" -Namespace "root\WMI").BaseBoardProduct.Trim()
                $ComputerDetails.BIOSVersionProperty = 'Version'
            }
        }

        # Handle output to log file for computer details
        Write-CMLogEntry -Value " - Computer manufacturer determined as: $($ComputerDetails.Manufacturer)" -Severity 1
        Write-CMLogEntry -Value " - Computer model determined as: $($ComputerDetails.Model)" -Severity 1
        Write-CMLogEntry -Value " - Computer BIOS version property determined as: $($ComputerDetails.BIOSVersionProperty)" -Severity 1

        # Handle output to log file for computer SystemSKU
        if (-not ([string]::IsNullOrEmpty($ComputerDetails.SystemSKU))) {
            Write-CMLogEntry -Value " - Computer SystemSKU determined as: $($ComputerDetails.SystemSKU)" -Severity 1
        }
        else {
            Write-CMLogEntry -Value " - Computer SystemSKU determined as: <null>" -Severity 2
            if (-not ([string]::IsNullOrEmpty($ComputerDetails.FallBackSKU))) {
                Write-CMLogEntry -Value " - Replacing Null SystemSKU with Fallback SystemSKU: $($ComputerDetails.FallBackSKU)" -Severity 1
                $ComputerDetails.SystemSKU = $ComputerDetails.FallbackSKU
            }
        }

        # Handle output to log file for Fallback SKU
        if (-not ([string]::IsNullOrEmpty($ComputerDetails.FallBackSKU))) {
            Write-CMLogEntry -Value " - Computer Fallback SystemSKU determined as: $($ComputerDetails.FallBackSKU)" -Severity 1
        }

        # Handle return value from function
        if ($ImitateModel){
            $ComputerDetails.Model = 'HP ProBook 450 G3'
            $ComputerDetails.Manufacturer = 'HP'
            $ComputerDetails.SystemSKU = '8101'
            $ComputerDetails.BIOSVersionProperty = 'Version'
        }

        return $ComputerDetails
    }

    function Get-AvailableBIOSUpdate {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Property to search with.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('Model','SystemSKU')]
            [string]$QueryProperty,

            [parameter(Mandatory = $true, HelpMessage = 'Object of computer details')]
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$ComputerDetails
        )

        $errorLimit = 10
        $errors = 0

        # Set default query param to Model
        switch ($QueryProperty) {
            'Model' {
                $APIQueryParam = "Model=$($ComputerDetails.Model)"
                break;
            }
            'SystemSKU' {
                $APIQueryParam = "SystemSKU=$($ComputerDetails.SystemSKU)"
                break;
            }
        }

        # Instantiates connection to custom webservice using API key
        switch ($DebugMode) {
            $true {

                break;
            }
            $false {
                $URI = $TSEnvironment.Value("CustomWebServiceURI").Replace('/osd', '')
                $SecretKey = $TSEnvironment.Value("CustomWebServiceKey")
                Write-CMLogEntry -Value "[INFO] URI retrieved: $URI" -Severity 1
                break;
            }
        }


        $APICallParams = @{
            Headers     = @{
                "Content-Type"  = "application/json"
                "Authorization" = "Bearer $($SecretKey)"
            }
            Method      = 'GET'
            URI         = "$URI/reports/Get-CMBIOSPackage?$APIQueryParam"
            ErrorAction = "SilentlyContinue"
        }

        Write-CMLogEntry -Value "[INFO] Calling API for BIOS package information: $APIQueryParam" -Severity 1

        do {
            try {
                $APIResults = (Invoke-RestMethod @APICallParams)
            }
            catch {
                $success = $false
                $errors++
                Write-CMLogEntry -Value "Error occured: $PSItem - Sleeping for 90 seconds and trying again. Attempt $Errors of $Errorlimit" -Severity 3
                Start-Sleep -Seconds 90
                if ($errors -ge $errorLimit) {
                    Write-Host 'Error count exceeded, exiting'
                    exit 1
                }
            }
            finally {
                $Status = $APIResults[0].Status
            }

        }
        until ($Status -eq 'Success')

        return $APIResults
    }

    $ComputerDetails = Get-ComputerData

    $APIResults = Get-AvailableBIOSUpdate -QueryProperty Model -ComputerDetails $ComputerDetails

    switch ($APIResults.PackageID.Count) {
        '0' {
            ## No results found, retry with SystemSKU if available
            Write-CMLogEntry -Value "[INFO] Returned zero packages for $($ComputerDetails.Model), retrying with SystemSKU" -Severity 1
            $APIResults = Get-AvailableBIOSUpdate -QueryProperty SystemSKU -ComputerDetails $ComputerDetails
            Write-CMLogEntry -Value "[INFO] API call returned: $($APIResults.PackageID.Count)" -Severity 1
            break;
        }
        '1' {
            ## Found one result, continue
            Write-CMLogEntry -Value "[INFO] Returned one package for $($ComputerDetails.Model), continuing" -Severity 1
            break;
        }
        { $PSItem -ge 2 } {
            ## Found two or more results, re-check with SKU
            Write-CMLogEntry -Value "[INFO] Returned two or more packages for $($ComputerDetails.Model), retrying with SystemSKU" -Severity 1
            $APIResults = Get-AvailableBIOSUpdate -QueryProperty SystemSKU -ComputerDetails $ComputerDetails
            Write-CMLogEntry -Value "[INFO] API call returned: $($APIResults.PackageID.Count)" -Severity 1
            break;
        }
    }


    if ($APIResults.PackageID.Count -ne 1) {
        $Parameters = @{
            Value    = "[WARNING] Returned number of BIOS packages is not equal to 1. Attempting to select most relevant."
            Severity = 2
        }
        Write-CMLogEntry @Parameters

        $APIResults = $APIResults | Where-Object Description -Match $ComputerDetails.SystemSKU
    }

    $AvailableBIOSVersion = $APIResults.$($ComputerDetails.BIOSVersionProperty)

    switch ($ComputerDetails.BIOSVersionProperty) {
        'Description' {
            $AvailableBIOSVersion = $AvailableBIOSVersion.Split(':')[2].Split(')')[0] # This retrieves 'ReleaseDate' from the package
            Compare-BIOSVersion -AvailableBIOSReleaseDate $AvailableBIOSVersion -ComputerManufacturer $ComputerDetails.Manufacturer
            break;
        }
        'Version' {
            Compare-BIOSVersion -AvailableBIOSVersion $AvailableBIOSVersion -ComputerManufacturer $ComputerDetails.Manufacturer
            break;
        }
    }

    if ($APIResults.Description -match '=') {
        Write-CMLogEntry -Value "[INFO] Special BIOS detected. Checking for conditions (Phase or prereq)" -Severity 1
        $Object = $APIResults.Description.Split(")")
        $Object | ForEach-Object {
            switch -Wildcard ($PSItem) {
                "*Phase*" {
                    $Phase = $PSItem.Split('=')[1]
                    $TSEnvironment.Value("BIOSPhase") = $Phase
                    Write-CMLogEntry -Value "[INFO] Special BIOS detected. Must run in $Phase" -Severity 1
                }
                "*PreReq*" {
                    $PreReq = $PSItem.Split('=')[1]
                    $TSEnvironment.Value("BIOSPreReq") = $PreReq
                    Write-CMLogEntry -Value "[INFO] Special BIOS detected. PreReq Version detected $PreReq" -Severity 1
                }
            }
        }
    }
    Write-CMLogEntry -Value "[INFO] API call results: $AvailableBIOSVersion" -Severity 1
}
