<#
.SYNOPSIS
    Build/emit/run automation for the OG Xbox recompiler SDK.

.DESCRIPTION
    One entry point for the inner loop that was being retyped as ad-hoc
    PowerShell every iteration (runP.ps1, runQ.ps1, ...). Verbs:

      ogx tool                 build the ogxbox recompiler itself
      ogx emit                 run `ogxbox emit` for a title config
      ogx build                cmake-configure + build the generated recomp
      ogx run                  run recomp.exe, tail the filtered stderr
      ogx cycle                tool -> emit -> build -> run (the whole loop)

    `emit` already copies the full runtime + kernel tree into the output dir,
    so no manual file copying is needed.

.EXAMPLE
    pwsh scripts/ogx.ps1 cycle -Trace
    pwsh scripts/ogx.ps1 cycle -Config configs/xmen-legends.toml -Out C:\tmp\ogx -Trace -Timeout 30
    pwsh scripts/ogx.ps1 run  -Out C:\tmp\ogx -Filter 'guest calls|ACCESS'
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory)]
    [ValidateSet('tool', 'emit', 'build', 'run', 'cycle')]
    [string]$Verb,

    [string]$Xbe    = "D:\My Games\Xbox recomp tools\extract-xiso\X-Men Legends (World).xiso\default.xbe",
    [string]$Config = "configs/xmen-legends.toml",
    [string]$Out    = (Join-Path $env:TEMP "ogx-out"),

    [switch]$Trace,
    [int]$Timeout   = 25,
    [string]$Filter = 'STACK:|ABI:|guest calls|ACCESS|abort|spin stack|^\s+sub_00|unimplemented|BugCheck|KERNEL',

    # toolchain overrides; auto-detected when blank
    [string]$VsVars = "",
    [string]$ExtraCFlags = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ToolDir  = Join-Path $RepoRoot "build"
$ToolExe  = Join-Path $ToolDir "ogxbox.exe"

function Find-VsVars {
    if ($VsVars -and (Test-Path $VsVars)) { return $VsVars }
    $bases = @(
        "C:\Program Files\Microsoft Visual Studio",
        "C:\Program Files (x86)\Microsoft Visual Studio"
    )
    foreach ($b in $bases) {
        if (-not (Test-Path $b)) { continue }
        $hit = Get-ChildItem $b -Recurse -Filter vcvars64.bat -ErrorAction SilentlyContinue |
               Sort-Object FullName -Descending | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    throw "vcvars64.bat not found; pass -VsVars <path>"
}

function Import-VsEnv {
    $bat = Find-VsVars
    Write-Host "=== VS env: $bat"
    cmd /c "`"$bat`" >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
    }
    foreach ($p in @("C:\Program Files\LLVM\bin", "C:\Program Files\CMake\bin")) {
        if ((Test-Path $p) -and ($env:PATH -notlike "*$p*")) { $env:PATH = "$p;$env:PATH" }
    }
}

function Invoke-Checked([string]$what, [scriptblock]$block) {
    & $block
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

function Step-Tool {
    Import-VsEnv
    if (-not (Test-Path (Join-Path $ToolDir "CMakeCache.txt"))) {
        Write-Host "=== cmake configure (tool)"
        Invoke-Checked "tool configure" { cmake -S $RepoRoot -B $ToolDir -G Ninja `
            -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl }
    }
    Write-Host "=== build ogxbox"
    Invoke-Checked "tool build" { cmake --build $ToolDir --target ogxbox }
    if (-not (Test-Path $ToolExe)) { throw "ogxbox.exe missing after build: $ToolExe" }
}

function Step-Emit {
    if (-not (Test-Path $ToolExe)) { throw "no ogxbox.exe - run 'ogx tool' first" }
    if (-not (Test-Path $Xbe))     { throw "xbe not found: $Xbe" }
    $cfgPath = Join-Path $RepoRoot $Config
    if (-not (Test-Path $cfgPath)) { throw "config not found: $cfgPath" }
    Write-Host "=== emit -> $Out"
    Push-Location $RepoRoot
    try {
        & $ToolExe emit $Xbe -o $Out --config $Config
        # exit 3 == validation errors: expected during bring-up, output is still
        # written and compiles. Only a missing CMakeLists means emit truly failed.
        if (-not (Test-Path (Join-Path $Out "CMakeLists.txt"))) {
            throw "emit produced no project (exit $LASTEXITCODE)"
        }
        if ($LASTEXITCODE -ne 0) { Write-Warning "emit exit $LASTEXITCODE (validation errors) - continuing" }
    } finally { Pop-Location }
}

function Step-Build {
    if (-not (Test-Path (Join-Path $Out "CMakeLists.txt"))) {
        throw "no generated project in $Out - run 'ogx emit' first"
    }
    Import-VsEnv
    $bt = Join-Path $Out "bt"
    $cflags = @()
    if ($Trace)       { $cflags += "-DREX_TRACE" }
    if ($ExtraCFlags) { $cflags += $ExtraCFlags }
    $cmakeArgs = @("-S", $Out, "-B", $bt, "-G", "Ninja",
                   "-DCMAKE_C_COMPILER=clang-cl", "-DCMAKE_CXX_COMPILER=clang-cl")
    if ($cflags.Count) { $cmakeArgs += "-DCMAKE_C_FLAGS=$($cflags -join ' ')" }
    Write-Host "=== cmake configure (recomp)  flags: $($cflags -join ' ')"
    Invoke-Checked "recomp configure" { cmake @cmakeArgs }
    Write-Host "=== build recomp"
    Invoke-Checked "recomp build" { cmake --build $bt }
}

function Step-Run {
    $bt  = Join-Path $Out "bt"
    $exe = Join-Path $bt "recomp.exe"
    if (-not (Test-Path $exe)) { throw "no recomp.exe in $bt - run 'ogx build' first" }
    $errLog = Join-Path $bt "e.log"
    $outLog = Join-Path $bt "o.log"
    Write-Host "=== run (timeout ${Timeout}s)"
    $p = Start-Process $exe -WorkingDirectory $Out -NoNewWindow -PassThru `
         -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    if (-not $p.WaitForExit($Timeout * 1000)) { $p.Kill(); Write-Host "  (killed at ${Timeout}s)" }
    else { Write-Host "  exit 0x$('{0:X}' -f $p.ExitCode)" }
    Write-Host "--- stderr (filter: $Filter) ---"
    if (Test-Path $errLog) { Get-Content $errLog | Select-String -Pattern $Filter }
}

switch ($Verb) {
    'tool'  { Step-Tool }
    'emit'  { Step-Emit }
    'build' { Step-Build }
    'run'   { Step-Run }
    'cycle' { Step-Tool; Step-Emit; Step-Build; Step-Run }
}
