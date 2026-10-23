
[CmdletBinding()]
param(
    [ValidateRange(1, 100)]
    [int]$MinimumFreePercent = 10,

    [ValidateRange(1, 30)]
    [int]$MaxSignatureAgeDays = 7
)

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$reportDirectory = Join-Path $projectRoot 'reports'
$outputPath = Join-Path $reportDirectory 'workstation-security-health-audit.csv'
$script:auditTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$script:results = [System.Collections.Generic.List[object]]::new()

function Add-AuditResult {
    param(
        [string]$CheckName,
        [string]$Category,
        [ValidateSet('Pass', 'Review', 'UnableToAssess', 'Info')]
        [string]$Status,
        [string]$ObservedValue,
        [string]$Finding,
        [string]$Recommendation
    )

    $script:results.Add([pscustomobject]@{
        AuditTimestamp  = $script:auditTimestamp
        CheckName       = $CheckName
        Category        = $Category
        Status          = $Status
        ObservedValue   = $ObservedValue
        Finding         = $Finding
        Recommendation  = $Recommendation
    })
}

# 1. Collect operating-system information without recording the computer name.
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

    if ($null -eq $os) {
        Add-AuditResult `
            -CheckName 'Operating system information' `
            -Category 'System' `
            -Status 'UnableToAssess' `
            -ObservedValue 'No information returned' `
            -Finding 'Operating system details could not be retrieved.' `
            -Recommendation 'Check whether the operating-system information source is available.'
    }
    else {
        $osDescription = '{0}; version {1}; build {2}' -f `
            $os.Caption, $os.Version, $os.BuildNumber

        Add-AuditResult `
            -CheckName 'Operating system information' `
            -Category 'System' `
            -Status 'Info' `
            -ObservedValue $osDescription `
            -Finding 'Operating system details collected.' `
            -Recommendation 'Compare the reported version and build with the organisation’s approved servicing policy.'
    }
}
catch {
    Add-AuditResult `
        -CheckName 'Operating system information' `
        -Category 'System' `
        -Status 'UnableToAssess' `
        -ObservedValue 'Query failed; technical details omitted from report' `
        -Finding 'Operating system details could not be retrieved.' `
        -Recommendation 'Check command availability and permissions.'
}

# 2. Inspect Microsoft Defender status where its cmdlet is available.
$defenderCommand = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue

if ($null -eq $defenderCommand) {
    Add-AuditResult `
        -CheckName 'Microsoft Defender status' `
        -Category 'Antivirus' `
        -Status 'UnableToAssess' `
        -ObservedValue 'Get-MpComputerStatus is unavailable' `
        -Finding 'Defender status could not be assessed using the expected cmdlet.' `
        -Recommendation 'Verify the installed security tools and available PowerShell commands.'
}
else {
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop

        if ($null -eq $defender) {
            throw 'No Defender status information returned.'
        }

        $booleanChecks = @(
            [pscustomobject]@{
                Property = 'AntivirusEnabled'
                Label = 'Microsoft Defender antivirus'
            }
            [pscustomobject]@{
                Property = 'AMServiceEnabled'
                Label = 'Microsoft Antimalware service'
            }
            [pscustomobject]@{
                Property = 'AntispywareEnabled'
                Label = 'Microsoft Defender antispyware'
            }
            [pscustomobject]@{
                Property = 'RealTimeProtectionEnabled'
                Label = 'Microsoft Defender real-time protection'
            }
        )

        foreach ($check in $booleanChecks) {
            $property = $defender.PSObject.Properties[$check.Property]

            if ($null -eq $property -or $null -eq $property.Value) {
                Add-AuditResult `
                    -CheckName $check.Label `
                    -Category 'Antivirus' `
                    -Status 'UnableToAssess' `
                    -ObservedValue 'Status property unavailable' `
                    -Finding 'The expected protection status was not returned.' `
                    -Recommendation 'Verify the security product and its reported status.'
            }
            else {
                $enabled = [bool]$property.Value

                if ($enabled) {
                    $status = 'Pass'
                    $finding = 'The queried protection feature reports enabled.'
                    $recommendation = 'Continue monitoring according to the organisation’s security policy.'
                }
                else {
                    $status = 'Review'
                    $finding = 'The queried protection feature does not report enabled.'
                    $recommendation = 'Verify the device security configuration and whether another approved security product is responsible for protection.'
                }

                Add-AuditResult `
                    -CheckName $check.Label `
                    -Category 'Antivirus' `
                    -Status $status `
                    -ObservedValue ([string]$enabled) `
                    -Finding $finding `
                    -Recommendation $recommendation
            }
        }

        # Check the age of the reported Defender antivirus signatures.
        $signatureProperty = $defender.PSObject.Properties['AntivirusSignatureLastUpdated']

        if (
            $null -eq $signatureProperty -or
            $null -eq $signatureProperty.Value
        ) {
            Add-AuditResult `
                -CheckName 'Defender signature age' `
                -Category 'Antivirus' `
                -Status 'UnableToAssess' `
                -ObservedValue 'Signature update date unavailable' `
                -Finding 'The age of Defender antivirus signatures could not be calculated.' `
                -Recommendation 'Check Microsoft Defender protection updates.'
        }
        else {
            try {
                $signatureDate = [datetime]$signatureProperty.Value
                $ageDays = ((Get-Date) - $signatureDate).TotalDays

                if ($ageDays -lt 0) {
                    $signatureStatus = 'Review'
                    $signatureFinding = 'Signature timestamp is in the future.'
                    $signatureRecommendation = 'Verify the system clock and reported signature update information.'
                }
                elseif ($ageDays -gt $MaxSignatureAgeDays) {
                    $signatureStatus = 'Review'
                    $signatureFinding = 'Signature age exceeds the configured review threshold.'
                    $signatureRecommendation = 'Check Microsoft Defender protection updates and confirm the current signature status.'
                }
                else {
                    $signatureStatus = 'Pass'
                    $signatureFinding = 'Signature age is within the configured review threshold.'
                    $signatureRecommendation = 'Continue monitoring signature status.'
                }

                Add-AuditResult `
                    -CheckName 'Defender signature age' `
                    -Category 'Antivirus' `
                    -Status $signatureStatus `
                    -ObservedValue ('Last updated {0}; age {1:N1} days' -f `
                        $signatureDate.ToString('yyyy-MM-dd HH:mm'), $ageDays) `
                    -Finding $signatureFinding `
                    -Recommendation $signatureRecommendation
            }
            catch {
                Add-AuditResult `
                    -CheckName 'Defender signature age' `
                    -Category 'Antivirus' `
                    -Status 'UnableToAssess' `
                    -ObservedValue 'Signature update date could not be interpreted' `
                    -Finding 'The signature age could not be calculated.' `
                    -Recommendation 'Verify the signature update information in Windows Security.'
            }
        }
    }
    catch {
        Add-AuditResult `
            -CheckName 'Microsoft Defender status query' `
            -Category 'Antivirus' `
            -Status 'UnableToAssess' `
            -ObservedValue 'Query failed; technical details omitted from report' `
            -Finding 'Defender status could not be fully retrieved.' `
            -Recommendation 'Check the security cmdlet, service status, and required permissions.'
    }
}

# 3. Inspect Windows Firewall profiles.
$firewallCommand = Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue

if ($null -eq $firewallCommand) {
    Add-AuditResult `
        -CheckName 'Windows Firewall profiles' `
        -Category 'Firewall' `
        -Status 'UnableToAssess' `
        -ObservedValue 'Get-NetFirewallProfile is unavailable' `
        -Finding 'Firewall profile states could not be assessed.' `
        -Recommendation 'Verify the availability of Windows Firewall management cmdlets.'
}
else {
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)

        if ($profiles.Count -eq 0) {
            Add-AuditResult `
                -CheckName 'Windows Firewall profiles' `
                -Category 'Firewall' `
                -Status 'UnableToAssess' `
                -ObservedValue 'No firewall profiles returned' `
                -Finding 'No firewall profiles were returned for inspection.' `
                -Recommendation 'Verify Firewall cmdlet output and device configuration.'
        }
        else {
            foreach ($profile in $profiles) {
                if ($null -eq $profile.Enabled) {
                    $firewallStatus = 'UnableToAssess'
                    $firewallValue = 'Unknown'
                    $firewallFinding = 'The profile enabled state was unavailable.'
                    $firewallRecommendation = 'Verify the selected firewall profile.'
                }
                elseif ([bool]$profile.Enabled) {
                    $firewallStatus = 'Pass'
                    $firewallValue = 'Enabled'
                    $firewallFinding = 'The firewall profile reports enabled.'
                    $firewallRecommendation = 'Continue monitoring according to the approved firewall policy.'
                }
                else {
                    $firewallStatus = 'Review'
                    $firewallValue = 'Disabled'
                    $firewallFinding = 'The firewall profile reports disabled.'
                    $firewallRecommendation = 'Verify the approved firewall policy before changing the profile.'
                }

                Add-AuditResult `
                    -CheckName ('Windows Firewall - {0}' -f $profile.Name) `
                    -Category 'Firewall' `
                    -Status $firewallStatus `
                    -ObservedValue $firewallValue `
                    -Finding $firewallFinding `
                    -Recommendation $firewallRecommendation
            }
        }
    }
    catch {
        Add-AuditResult `
            -CheckName 'Windows Firewall profiles' `
            -Category 'Firewall' `
            -Status 'UnableToAssess' `
            -ObservedValue 'Query failed; technical details omitted from report' `
            -Finding 'Firewall profile states could not be retrieved.' `
            -Recommendation 'Check command availability, device configuration, and permissions.'
    }
}

# 4. Check C: drive free space.
try {
    $systemDrive = Get-CimInstance `
        -ClassName Win32_LogicalDisk `
        -Filter "DeviceID='C:'" `
        -ErrorAction Stop

    if (
        $null -eq $systemDrive -or
        [double]$systemDrive.Size -le 0
    ) {
        Add-AuditResult `
            -CheckName 'System drive free space' `
            -Category 'Storage' `
            -Status 'UnableToAssess' `
            -ObservedValue 'C: drive capacity unavailable' `
            -Finding 'System drive capacity could not be calculated.' `
            -Recommendation 'Verify the system drive and storage information source.'
    }
    else {
        $sizeGB = [double]$systemDrive.Size / 1GB
        $freeGB = [double]$systemDrive.FreeSpace / 1GB
        $freePercent = ([double]$systemDrive.FreeSpace / [double]$systemDrive.Size) * 100

        if ($freePercent -lt $MinimumFreePercent) {
            $diskStatus = 'Review'
            $diskFinding = 'Free space is below the configured threshold.'
            $diskRecommendation = 'Review storage usage and approved cleanup options before removing files.'
        }
        else {
            $diskStatus = 'Pass'
            $diskFinding = 'Free space is at or above the configured threshold.'
            $diskRecommendation = 'Continue monitoring available storage.'
        }

        Add-AuditResult `
            -CheckName 'System drive free space' `
            -Category 'Storage' `
            -Status $diskStatus `
            -ObservedValue ('{0:N1} GB free of {1:N1} GB ({2:N1}% free)' -f `
                $freeGB, $sizeGB, $freePercent) `
            -Finding $diskFinding `
            -Recommendation $diskRecommendation
    }
}
catch {
    Add-AuditResult `
        -CheckName 'System drive free space' `
        -Category 'Storage' `
        -Status 'UnableToAssess' `
        -ObservedValue 'Query failed; technical details omitted from report' `
        -Finding 'System drive free space could not be retrieved.' `
        -Recommendation 'Check the storage information source and permissions.'
}

# 5. Export the report without including computer name, username, or IP addresses.
if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $reportDirectory -Force |
        Out-Null
}

$script:results |
    Export-Csv -LiteralPath $outputPath -NoTypeInformation -Encoding UTF8

$reviewCount = @($script:results | Where-Object Status -eq 'Review').Count
$unableCount = @($script:results | Where-Object Status -eq 'UnableToAssess').Count
$passCount = @($script:results | Where-Object Status -eq 'Pass').Count
$infoCount = @($script:results | Where-Object Status -eq 'Info').Count

Write-Host "`nWorkstation security and health audit completed." -ForegroundColor Green
Write-Host "Checks reporting Pass: $passCount"
Write-Host "Checks needing review: $reviewCount"
Write-Host "Checks unable to assess: $unableCount"
Write-Host "Informational checks: $infoCount"
Write-Host "Report saved to: $outputPath"
Write-Host 'No Windows settings were changed.'

$script:results |
    Format-Table CheckName, Category, Status, ObservedValue -Wrap -AutoSize
