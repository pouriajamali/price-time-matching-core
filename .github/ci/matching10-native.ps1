# Original native cases, guarded inputs admitted before build. Source/event/caps are owned by hosted_caps.py.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Hosted native rows only' }
if ($IsWindows) {
  $imageAllowed = $env:ImageOS -ceq 'win25' -or ($env:ImageOS -ceq 'win25-vs2026' -and $env:ImageVersion -ceq '20261103.298.1')
  if (-not $imageAllowed -or -not $env:MATCHING10_HOST_OBSERVATION) { throw 'Unsupported Windows hosted image' }
  $hostProof = Get-Content -LiteralPath $env:MATCHING10_HOST_OBSERVATION -Raw | ConvertFrom-Json
  if ($hostProof.status -cne 'SUPPORTED_HOSTED_NATIVE_OS_OBSERVED' -or $hostProof.source -cne $env:GITHUB_SHA -or
      $hostProof.imageOS -cne $env:ImageOS -or $hostProof.imageVersion -cne $env:ImageVersion -or
      $hostProof.system -cne 'Windows' -or $hostProof.runnerOS -cne 'Windows' -or $hostProof.runnerArch -cne 'X64' -or
      $hostProof.pointerBits -ne 64 -or $hostProof.ntVersion.major -ne 10 -or $hostProof.ntVersion.minor -ne 0 -or
      $hostProof.ntVersion.build -ne 26100 -or $hostProof.ntVersion.productType -ne 3 -or
      $hostProof.processMachine -ne 0 -or $hostProof.nativeMachine -ne 34404) { throw 'Actual native Server2025/build26100/x64 proof mismatch' }
} elseif ($env:ImageOS -cne 'ubuntu24') { throw 'Hosted native rows only' }
if (-not $env:MATCHING10_PACKAGE_ADMISSION) { throw 'Package admission absent' }
$admission = Get-Content -LiteralPath $env:MATCHING10_PACKAGE_ADMISSION -Raw | ConvertFrom-Json
if ($admission.status -ne 'EXACT_PACKAGE_INPUTS_ADMITTED' -or $admission.source -ne $env:GITHUB_SHA) { throw 'Package admission/source mismatch' }
function Mark-Phase([string]$name) {
  python .github/ci/hosted_caps.py --mark-stage $name --context $env:MATCHING10_CONTEXT --context-sha256 $env:MATCHING10_CONTEXT_SHA256
  if ($LASTEXITCODE -ne 0) { throw 'Own stage marker failed' }
}
# Original stage: Locked source tests
# The original locked restore is executed once by the input gate, with offline-only sources and unchanged locks.
Mark-Phase build
dotnet build PriceTimeMatching.slnx -c Release --no-restore -m:1 -p:UseSharedCompilation=false -nodeReuse:false
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:MATCHING_CAPACITY_EVIDENCE = Join-Path (Get-Location) 'artifacts/capacity-csharp.json'
Mark-Phase unit
dotnet run --project tests/Matching.Tests/Matching.Tests.csproj -c Release --no-build -- -result-xml artifacts/unit.xml
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Original stage: Independent capacity model in three interpreter modes
Mark-Phase model
python tools/test_capacity_model.py --fixtures tests/Matching.Tests/Fixtures/capacity-model-v1.json --out artifacts/capacity-model --matrix
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Original stage: Verify exact model membership, identities and application cap
Mark-Phase modelcheck
python tools/test_capacity_model.py --fixtures tests/Matching.Tests/Fixtures/capacity-model-v1.json --out artifacts/capacity-model --check-matrix
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Original stage: Build exact clean native package
Mark-Phase package
python tools/package.py --rid $env:MATCHING10_RID --commit $env:GITHUB_SHA --work artifacts/build --out artifacts/delivery
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Original stage: Canonical pinned-key and attacker-signature regressions
Mark-Phase verifier
python tools/test_verifier.py --out artifacts/verifier-tests
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Original stage: Current advisory data for locked dependencies
# Original tools/audit_dependencies.py is run once BEFORE build by the actual input gate; check its retained result here.
$advisory = Get-Content -LiteralPath artifacts/dependency-advisories.json -Raw | ConvertFrom-Json
if ($advisory.status -ne 'NO_KNOWN_ADVISORIES_REPORTED') { throw 'Original advisory check failed' }
# Original stage: Extract and execute the actual package
Mark-Phase packagecheck
$archive = @(Get-ChildItem artifacts/delivery -File)
if ($archive.Count -ne 1) { throw 'Exactly one archive required' }
python tools/extract_package.py --archive $archive[0].FullName --out 'artifacts/extracted with spaces'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$package = @(Get-ChildItem 'artifacts/extracted with spaces' -Directory)
if ($package.Count -ne 1) { throw 'Exactly one package root required' }
python tools/check_package.py --package $package[0].FullName --commit $env:GITHUB_SHA --out artifacts/package-checks.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Original stage: Native deterministic replay and independent model
Mark-Phase native-demo
$package = @(Get-ChildItem 'artifacts/extracted with spaces' -Directory)
$name = if ($IsWindows) { 'matching.exe' } else { 'matching' }
python tools/native_demo.py --cli (Join-Path $package[0].FullName $name) --out artifacts/native-demo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
