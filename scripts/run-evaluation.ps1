<#
.SYNOPSIS
    Convenience wrapper: evaluate one synthetic plan fixture and write an evidence bundle.

.DESCRIPTION
    Calls the offline evaluator (python -m iac_change_control.cli evaluate) with the project
    virtual environment if it exists. Everything is local: no cloud account, no credentials,
    no Terraform execution. The script returns the evaluator's exit code:
    0 = PASS or WARN, 1 = BLOCKED, 2 = ERROR.

.EXAMPLE
    ./scripts/run-evaluation.ps1 -Plan fixtures/plans/compliant.json `
        -Approval fixtures/approvals/approved-change.json -RunId fixture-compliant-v1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Plan,
    [string]$Approval,
    [string]$Policy = 'policy/policy-config.json',
    [string]$Output,
    [Parameter(Mandatory = $true)][string]$RunId
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$Python = if (Test-Path $VenvPython) { $VenvPython } else { 'python' }
if (-not $Output) { $Output = Join-Path 'evidence' ("run-" + $RunId) }

$cliArgs = @('-m', 'iac_change_control.cli', 'evaluate',
    '--plan', $Plan, '--policy', $Policy, '--output', $Output, '--run-id', $RunId)
if ($Approval) { $cliArgs += @('--approval', $Approval) }

Push-Location $ProjectRoot
try {
    & $Python @cliArgs
    $code = $LASTEXITCODE
}
finally {
    Pop-Location
}
exit $code
