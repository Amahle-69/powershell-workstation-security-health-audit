
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$auditScript = Join-Path $projectRoot 'scripts\Test-WorkstationSecurityHealth.ps1'
$reportPath = Join-Path $projectRoot 'reports\workstation-security-health-audit.csv'

$script:passed = 0
$script:failed = 0

function Assert-True {
    param(
        [string]$Name,
        [bool]$Condition
    )

    if ($Condition) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
        $script:passed++
    }
    else {
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        $script:failed++
    }
}

# Check the audit script exists.
Assert-True `
    -Name 'Workstation audit script exists' `
    -Condition (Test-Path -LiteralPath $auditScript -PathType Leaf)

if (-not (Test-Path -LiteralPath $auditScript -PathType Leaf)) {
    throw 'Cannot run report tests because the audit script is missing.'
}

# Generate a fresh report using the normal project output path.
& $auditScript | Out-Null

Assert-True `
    -Name 'Audit report was generated' `
    -Condition (Test-Path -LiteralPath $reportPath -PathType Leaf)

if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
    throw 'Cannot continue because the audit report was not generated.'
}

$results = @(Import-Csv -LiteralPath $reportPath)

Assert-True `
    -Name 'Audit report contains results' `
    -Condition ($results.Count -ge 4)

# Verify expected report columns.
$requiredColumns = @(
    'AuditTimestamp',
    'CheckName',
    'Category',
    'Status',
    'ObservedValue',
    'Finding',
    'Recommendation'
)

$actualColumns = @($results[0].PSObject.Properties.Name)

$missingColumns = @(
    $requiredColumns |
        Where-Object { $actualColumns -notcontains $_ }
)

Assert-True `
    -Name 'All required report columns are present' `
    -Condition ($missingColumns.Count -eq 0)

# Verify that essential checks appear in the report.
Assert-True `
    -Name 'Operating system check is present' `
    -Condition (
        @($results | Where-Object {
            $_.CheckName -eq 'Operating system information'
        }).Count -eq 1
    )

Assert-True `
    -Name 'An antivirus check is present' `
    -Condition (
        @($results | Where-Object {
            $_.Category -eq 'Antivirus'
        }).Count -ge 1
    )

Assert-True `
    -Name 'A firewall check is present' `
    -Condition (
        @($results | Where-Object {
            $_.Category -eq 'Firewall'
        }).Count -ge 1
    )

Assert-True `
    -Name 'System drive storage check is present' `
    -Condition (
        @($results | Where-Object {
            $_.CheckName -eq 'System drive free space'
        }).Count -eq 1
    )

# Status must be one of the documented values.
$allowedStatuses = @('Pass', 'Review', 'UnableToAssess', 'Info')

$invalidStatuses = @(
    $results | Where-Object {
        $_.Status -notin $allowedStatuses
    }
)

Assert-True `
    -Name 'All audit results use documented statuses' `
    -Condition ($invalidStatuses.Count -eq 0)

# Each result should contain a finding and recommendation.
$incompleteResults = @(
    $results | Where-Object {
        [string]::IsNullOrWhiteSpace($_.Finding) -or
        [string]::IsNullOrWhiteSpace($_.Recommendation)
    }
)

Assert-True `
    -Name 'Every result contains a finding and recommendation' `
    -Condition ($incompleteResults.Count -eq 0)

# Verify the report does not include direct machine or user identifiers as columns.
$disallowedColumns = @(
    'ComputerName',
    'UserName',
    'Username',
    'IPAddress',
    'SerialNumber'
)

$exposedColumns = @(
    $actualColumns | Where-Object {
        $_ -in $disallowedColumns
    }
)

Assert-True `
    -Name 'Report schema excludes direct machine identifiers' `
    -Condition ($exposedColumns.Count -eq 0)

# Verify recorded status totals agree with the rows in the CSV.
$passCount = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
$reviewCount = @($results | Where-Object { $_.Status -eq 'Review' }).Count
$unableCount = @($results | Where-Object { $_.Status -eq 'UnableToAssess' }).Count
$infoCount = @($results | Where-Object { $_.Status -eq 'Info' }).Count

Assert-True `
    -Name 'Status totals account for every report row' `
    -Condition (
        ($passCount + $reviewCount + $unableCount + $infoCount) -eq $results.Count
    )

Write-Host "`nWorkstation audit test summary" -ForegroundColor Cyan
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"

if ($script:failed -gt 0) {
    throw 'One or more workstation audit tests failed.'
}

Write-Host "`nAll workstation audit report tests passed." -ForegroundColor Green
