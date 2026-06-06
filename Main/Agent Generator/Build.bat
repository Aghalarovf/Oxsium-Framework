@echo off
setlocal EnableDelayedExpansion

:: ─────────────────────────────────────────────────────────────────────────────
::  OxGen Build Script  —  v.14
::  Produces:  oxgen.exe   (single executable, no external DLLs except wldap32)
::
::  Requirements:
::    - MinGW-w64 or MSYS2 g++ in PATH  (g++ -v must work)
::    - Windows 10/11 (wldap32.dll is in System32)
::
::  Usage:
::    Build.bat              — release build → oxgen.exe
::    Build.bat debug        — debug build with symbols → oxgen_debug.exe
:: ─────────────────────────────────────────────────────────────────────────────

set "PROJECT_ROOT=%~dp0"

:: ── Output path ────────────────────────────────────────────────────────────
:: Priority: AG_OUTPUT env var (set by connection.py generate-agent endpoint)
:: Fallback : two levels up from "Agent Generator\" — the project root where
::            README.md lives  (i.e.  …\Oxsium-Framework\)
set "DEFAULT_OUTPUT=%PROJECT_ROOT%..\"

if defined AG_OUTPUT (
    if not "!AG_OUTPUT!"=="" (
        set "RESOLVED_OUTPUT=!AG_OUTPUT!"
    ) else (
        set "RESOLVED_OUTPUT=%DEFAULT_OUTPUT%"
    )
) else (
    set "RESOLVED_OUTPUT=%DEFAULT_OUTPUT%"
)

:: Ensure trailing backslash
if "!RESOLVED_OUTPUT:~-1!" NEQ "\" set "RESOLVED_OUTPUT=!RESOLVED_OUTPUT!\"

:: Create output directory if it does not exist
if not exist "!RESOLVED_OUTPUT!" (
    mkdir "!RESOLVED_OUTPUT!" 2>nul
    if errorlevel 1 (
        echo   [-] Could not create output directory: !RESOLVED_OUTPUT!
        exit /b 1
    )
    echo   [*] Created output directory: !RESOLVED_OUTPUT!
)

:: Agent executable name: AG_NAME env var or default "oxgen"
set "AGENT_NAME=oxgen"
if defined AG_NAME (
    if not "!AG_NAME!"=="" set "AGENT_NAME=!AG_NAME!"
)

set "OUT_EXE=!RESOLVED_OUTPUT!!AGENT_NAME!.exe"
set "OUT_DBG=!RESOLVED_OUTPUT!!AGENT_NAME!_debug.exe"

:: Detect debug flag
set "DEBUG_BUILD=0"
if /i "%1"=="debug" set "DEBUG_BUILD=1"

:: ── Compiler check ────────────────────────────────────────────────────────
where g++ >nul 2>&1
if errorlevel 1 (
    echo   [-] g++ not found. Install MinGW-w64 or MSYS2 and add it to PATH.
    echo       e.g.  scoop install mingw   or   winget install MinGW.MinGW
    exit /b 1
)
for /f "tokens=*" %%V in ('g++ --version 2^>^&1 ^| findstr /r "g++"') do echo   [*] Compiler: %%V

:: ── Source files ──────────────────────────────────────────────────────────
set "SOURCES="
set "SOURCES=%SOURCES% "%PROJECT_ROOT%main.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%src\ldap_engine.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%src\ldap_helper.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\user\user_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\group\group_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\ace\ace_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\computer\computer_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp1.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp2.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp3.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp4.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp5.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp6.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp7.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp8.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp9.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp10.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp11.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\offline processor\offline_processorp12.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\ou\ou_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\gpo\gpo_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\certificate\cert_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\dominfo\dominfo_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\trust\trust_collector.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\network\network_collectorp1.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\network\network_collectorp2.cpp""
set "SOURCES=%SOURCES% "%PROJECT_ROOT%modules\network\network_collectorp3.cpp""

:: ── Compiler flags ────────────────────────────────────────────────────────
set "CXXFLAGS=-std=c++17 -Wall -Wextra -Wno-unused-parameter"
set "CXXFLAGS=%CXXFLAGS% -Wno-cast-function-type"
set "CXXFLAGS=%CXXFLAGS% -DUNICODE -D_UNICODE"
set "CXXFLAGS=%CXXFLAGS% -I"%PROJECT_ROOT%include""

:: Suppress WinLDAP redefinition warnings (our ldap.h + winldap.h overlap)
set "CXXFLAGS=%CXXFLAGS% -Wno-ignored-attributes -Wno-attributes"

if "%DEBUG_BUILD%"=="1" (
    set "CXXFLAGS=%CXXFLAGS% -g -O0 -DDEBUG"
    set "OUT_EXE=!OUT_DBG!"
    echo   [*] Mode: DEBUG
) else (
    set "CXXFLAGS=%CXXFLAGS% -O2 -DNDEBUG"
    echo   [*] Mode: RELEASE
)

set "BUILD_LOG=%PROJECT_ROOT%build.log"

:: ── zlib (ZIP sıxışdırması üçün) ───────────────────────────────────────────
:: MinGW ilə birlikdə gəlir — heç bir əlavə yükləmə lazım deyil.
set "LDFLAGS=%LDFLAGS% -lz -lkernel32 -luser32 -ladvapi32"
set "LDFLAGS=%LDFLAGS% -lwldap32 -liphlpapi -licmp -lws2_32"

:: ── Build ─────────────────────────────────────────────────────────────────
echo   [*] Compiling...
echo.

g++ %CXXFLAGS% %SOURCES% %LDFLAGS% -o "%OUT_EXE%" > "%BUILD_LOG%" 2>&1

if errorlevel 1 (
    echo.
    echo   [-] Build FAILED. See build.log for details:
    echo.
    type "%BUILD_LOG%"
    echo.
    exit /b 1
)

echo   [+] Build succeeded.
echo   [+] Output: %OUT_EXE%
echo.

:: ── Record build in PROJECT_MAP.md ────────────────────────────────────────
for /f "tokens=*" %%D in ('powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set "TS=%%D"
echo - %TS% : Built %~nx0 >> "%PROJECT_ROOT%PROJECT_MAP.md"

echo   [+] Build history updated in PROJECT_MAP.md
echo.

:: ── Quick size report ─────────────────────────────────────────────────────
for %%F in ("%OUT_EXE%") do (
    set /a "SIZE_KB=%%~zF/1024"
    echo   [*] Size: !SIZE_KB! KB
)

echo.
echo   ══════════════════════════════════════════
echo     Run:  %~nx0  [no arguments]
echo     Help: oxgen.exe  (then type 'help')
echo   ══════════════════════════════════════════
echo.