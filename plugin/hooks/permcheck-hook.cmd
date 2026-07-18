@echo off
setlocal EnableDelayedExpansion
rem permcheck PreToolUse hook wrapper (native Windows cmd.exe).
rem Mirrors permcheck-hook.sh. Fails OPEN (exit 0, no output) if the binary is
rem missing, so a platform mismatch never blocks every tool call.

set "ROOT=%CLAUDE_PLUGIN_ROOT%"
if "%ROOT%"=="" set "ROOT=%~dp0.."

set "ARCH=x64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
set "BIN=%ROOT%\bin\permcheck-windows-%ARCH%.exe"

if defined PERMCHECK_RULES (
  set "RULES=%PERMCHECK_RULES%"
) else if exist "%CLAUDE_PROJECT_DIR%\.permcheck\rules.json" (
  set "RULES=%CLAUDE_PROJECT_DIR%\.permcheck\rules.json"
) else (
  set "RULES=%ROOT%\rules\permcheck.json"
)

if not exist "%BIN%" exit /b 0

"%BIN%" --hook --rules "%RULES%"
