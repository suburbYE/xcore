:: X-Core build script (MSVC). The version lives in ..\VERSION and is projected
:: into src\version.h by scripts\sync_version.py; never write a version literal
:: into a source file or the --json output will drift from the banner again.
@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

echo [0/2] Syncing version from VERSION...
python "%~dp0scripts\sync_version.py"
if %errorlevel% neq 0 goto fail

set CFLAGS=/std:c++17 /EHsc /O2 /I src /DXCORE_NO_MAIN
set SQLITE_FLAGS=/DSQLITE_OMIT_DEPRECATED /DSQLITE_THREADSAFE=1 /DSQLITE_OMIT_LOAD_EXTENSION /DSQLITE_OMIT_JSON
:: Keep intermediate .obj files out of the repo root.
set OBJDIR=cache\obj

if not exist %OBJDIR% mkdir %OBJDIR%

echo [1/2] Building xcore.exe (unified)...
cl %CFLAGS% %SQLITE_FLAGS% /Fo:%OBJDIR%\ /Fe:xcore.exe src\main.cpp src\xcore.cpp src\llm_client.cpp src\case_db.cpp src\sqlite3.c /link bcrypt.lib
if %errorlevel% neq 0 goto fail

echo [2/2] Building tools\classify.exe (legacy)...
:: classify.cpp was removed from the repo in v0.13.0 (5a20cef). Skip when absent,
:: otherwise every build ends in [FAIL] and hides the real result.
if not exist tools\classify.cpp (
  echo   [SKIP] tools\classify.cpp not in repo - legacy target disabled.
  goto ok
)
cl %CFLAGS% %SQLITE_FLAGS% /Fo:%OBJDIR%\ /Fe:tools\classify.exe src\xcore.cpp src\llm_client.cpp src\case_db.cpp src\sqlite3.c tools\classify.cpp /link bcrypt.lib
if %errorlevel% neq 0 goto fail

:ok
echo.
echo [OK] All targets built.
goto end

:fail
echo [FAIL] Build failed.
:end
endlocal
