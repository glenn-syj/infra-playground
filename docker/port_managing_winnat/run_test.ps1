# 관리자 권한이 없으면 관리자 권한으로 다시 실행
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $scriptPath = $MyInvocation.MyCommand.Path
    $currentDirectory = Split-Path -Parent $scriptPath
    $arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$currentDirectory'; & '$scriptPath'`""
    Start-Process powershell -Verb RunAs -ArgumentList $arguments -Wait
    return
}

Write-Host "=== WinNAT Port Conflict Test ===" -ForegroundColor Green

# Windows 예약 포트 범위 확인
Write-Host "Checking Windows reserved ports..." -ForegroundColor Yellow
$excludedPorts = & "C:\Windows\System32\netsh.exe" interface ipv4 show excludedportrange protocol=tcp
Write-Host $excludedPorts

# 가상환경 설정
if (-not (Test-Path "venv")) {
    Write-Host "`nCreating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# 가상환경 활성화
Write-Host "`nActivating virtual environment..." -ForegroundColor Yellow
.\venv\Scripts\Activate.ps1

# 의존성 설치
Write-Host "`nInstalling dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# 테스트 실행
Write-Host "`nRunning port conflict test..." -ForegroundColor Yellow
python test_scenarios.py

Write-Host "`nTest completed!" -ForegroundColor Green 

# 실행 완료 후 대기
Write-Host "`nPress Enter to exit..." -ForegroundColor Yellow
Read-Host