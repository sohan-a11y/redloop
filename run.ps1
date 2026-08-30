# RedLoop entrypoint
param(
  [ValidateSet("status", "convergent", "plan", "add", "help")]
  [string]$Action = "status",
  [string]$Role,
  [string]$File
)

Set-Location -LiteralPath $PSScriptRoot

switch ($Action) {
  "status"    { python loop.py status }
  "convergent"{ python loop.py convergent }
  "plan"      { python loop.py plan -o PLAN.md; Get-Content PLAN.md }
  "add"       { if (-not $Role -or -not $File) { throw "need -Role and -File" }; python loop.py add -r $Role -f $File }
  "help"      { python loop.py -h }
}