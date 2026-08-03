@echo off
setlocal EnableDelayedExpansion
rem permcheck PreToolUse hook wrapper (native Windows cmd.exe).
rem Mirrors permcheck-hook.sh. Fails OPEN (exit 0, no output) if the binary is
rem missing, so a platform mismatch never blocks every tool call.

set "ROOT=%CLAUDE_PLUGIN_ROOT%"
if "%ROOT%"=="" set "ROOT=%~dp0.."

rem Only a windows-x64 binary is published (see .github/workflows/release.yml).
rem Windows on ARM runs it under x64 emulation, so there is no arch branch here;
rem adding one would point at a binary that is never built and fail open.
set "BIN=%ROOT%\bin\permcheck-windows-x64.exe"

if defined PERMCHECK_RULES (
  set "RULES=%PERMCHECK_RULES%"
) else if exist "%CLAUDE_PROJECT_DIR%\.permcheck\rules.json" (
  set "RULES=%CLAUDE_PROJECT_DIR%\.permcheck\rules.json"
) else (
  set "RULES=%ROOT%\rules\permcheck.json"
)

if not exist "%BIN%" exit /b 0

"%BIN%" --hook --rules "%RULES%"
