:: X-Core build script (MSVC) — unified binary v0.13.0
@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

set CFLAGS=/std:c++17 /EHsc /O2 /I src /DXCORE_NO_MAIN
set SQLITE_FLAGS=/DSQLITE_OMIT_DEPRECATED /DSQLITE_THREADSAFE=1 /DSQLITE_OMIT_LOAD_EXTENSION /DSQLITE_OMIT_JSON

echo [1/2] Building xcore.exe (unified)...
cl %CFLAGS% %SQLITE_FLAGS% /Fe:xcore.exe src\main.cpp src\xcore.cpp src\llm_client.cpp src\case_db.cpp src\sqlite3.c /link bcrypt.lib
if %errorlevel% neq 0 goto fail

echo [2/2] Building tools\classify.exe (legacy)...
cl %CFLAGS% %SQLITE_FLAGS% /Fe:tools\classify.exe src\xcore.cpp src\llm_client.cpp src\case_db.cpp src\sqlite3.c tools\classify.cpp /link bcrypt.lib
if %errorlevel% neq 0 goto fail

echo.
echo [OK] All targets built.
goto end

:fail
echo [FAIL] Build failed.
:end
endlocal
