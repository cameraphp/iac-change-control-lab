<#
.SYNOPSIS
    Optional, non-blocking Terraform-safe check for iac-change-control-lab (SAFE-005, V-TF-01).

.DESCRIPTION
    If Docker is available, runs a pinned hashicorp/terraform image with:
      - no container network (--network none) and CHECKPOINT_DISABLE=1;
      - only terraform-sample/ mounted, read-only;
      - exactly two subcommands: "version", then "fmt -check -recursive".
    terraform-sample/ is provider-free and resource-free. No provider is ever downloaded, and no
    other Terraform subcommand appears anywhere in this script.

    The core evaluator, the tests and the demo never depend on this script. If Docker or the
    engine is unavailable, the script prints SKIP with a reason and exits 0.

    Exit codes: 0 = PASS or SKIP; 1 = fmt check reported formatting differences or the
    container failed.

.PARAMETER TerraformImage
    Explicit, pinned image tag. Docker pulls it once if it is not present locally.
#>
[CmdletBinding()]
param(
    [string]$TerraformImage = 'hashicorp/terraform:1.14.0'
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$SampleDir = Join-Path $ProjectRoot 'terraform-sample'

function Write-Status([string]$Status, [string]$Message) {
    Write-Output ("TERRAFORM-SAFE-CHECK {0}: {1}" -f $Status, $Message)
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Status 'SKIP' 'docker CLI not found; the core evaluator does not need it.'
    exit 0
}
& docker info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Status 'SKIP' 'Docker engine not reachable; the core evaluator does not need it.'
    exit 0
}
if ($TerraformImage -notmatch '^hashicorp/terraform:\d+\.\d+\.\d+$') {
    Write-Status 'SKIP' 'image must be an explicit hashicorp/terraform:MAJOR.MINOR.PATCH tag.'
    exit 0
}

$containerArgs = @(
    'run', '--rm',
    '--network', 'none',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '-e', 'CHECKPOINT_DISABLE=1',
    '-v', "${SampleDir}:/work:ro",
    '-w', '/work',
    $TerraformImage
)

Write-Output "Image: $TerraformImage (container network disabled; sample mounted read-only)"
& docker @containerArgs 'version'
if ($LASTEXITCODE -ne 0) {
    Write-Status 'SKIP' "could not run $TerraformImage (image unavailable offline?)."
    exit 0
}
& docker @containerArgs 'fmt' '-check' '-recursive' '-diff'
if ($LASTEXITCODE -ne 0) {
    Write-Status 'FAIL' 'fmt -check reported formatting differences in terraform-sample/.'
    exit 1
}
Write-Status 'PASS' 'version printed and fmt -check clean (provider-free sample; nothing applied).'
exit 0
