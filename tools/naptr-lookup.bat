@ECHO OFF
REM This script looks up radsec srv records in DNS for the one
REM realm given as argument, and creates a server template based
REM on that. It currently ignores weight markers, but does sort
REM servers on priority marker, lowest number first.
REM For host command this is column 5, for dig it is column 1.
REM 
REM We key *everything* off the directory that this batchfile runs from:
cd %~dp0

REM We use delayed expansion in the loops, those variables use !var!, not %var%
SETLOCAL ENABLEDELAYEDEXPANSION

REM Uncomment the appropriate line for eduroam or OpenRoaming
REM eduroam
set NAPTR_PATTERN=x-eduroam:radius.tls
REM OpenRoaming
REM set NAPTR_PATTERN=aaa+auth:radius.tls.tcp

REM 
REM There is nothing else to edit from here!!
REM
if "x%~1"=="x" goto :usage
goto :start_validate

:usage
  echo Usage: %~0 ^<realm^>
  exit 1

:start_validate
REM our utilities - dig and host come from BIND9
set digcmd="%~dp0\bind\dig.exe"
set hostcmd="%~dp0\bind\host.exe"
REM our utilities - these all come from cygwin
set printcmd="%~dp0\printf.exe"
set echocmd="%~dp0\echo.exe"
set grepcmd="%~dp0\grep.exe"
set sedcmd="%~dp0\sed.exe"
set sortcmd="%~dp0\sort.exe"
set trcmd="%~dp0\tr.exe"

REM Here we go, validate the realm
call :FUNC_validate_host %1 ORIG_REALM

REM Check the whether the realm validated ok
if "%ORIG_REALM%x"=="x" (
  echo Error: realm "%1" failed validation
  goto :usage
)

REM Validate if the realm is a 3GPP one, if so, munge it for some of the functions
call :FUNC_validate_3gppnetwork %ORIG_REALM% REALM

REM Check the whether the realm validated ok
if "%REALM%x"=="x" (
  echo Error: realm "%1" failed validation
  goto :usage
)

REM
REM Now let's get on with the real thing.
REM

REM DIG for the NAPTR record
call :FUNC_dig_it_naptr %REALM%
IF NOT "x%SERVERS%" == "x" ( 
     %printcmd% "server dynamic_radsec.%ORIG_REALM% {\n%SERVERS%\n\ttype TLS\n}\n"
     exit 0
)

REM Go to the end of the batch file
goto :end

REM Beyond this point we only have functions (or subs, as Windows calls them)

:FUNC_validate_host
for /f "delims=" %%r in ('^"%echocmd% %1 ^|^"%trcmd% -d ^' \042\n\t\r\^'^'') do set validate_host_realm=%%r
for /f "delims=" %%r in ('^"%echocmd% %validate_host_realm% ^|^"%grepcmd% -E ^'^[_0-9a-zA-Z][-._0-9a-zA-Z]*$^'') do set validate_host_realm=%%r
for /f "delims=" %%r in ('^"%echocmd% %validate_host_realm% ^|^"%trcmd% ^'[:upper:]^' ^'[:lower:]^'') do set validate_host_realm=%%r
set %2=%validate_host_realm%
exit /b


:FUNC_validate_3gppnetwork
for /f "delims=" %%r in ('^"%echocmd% %1 ^|^"%grepcmd% ^'\.pub\.3gppnetwork\.org$^'') do set test3gpppub=%%r
for /f "delims=" %%r in ('^"%echocmd% %1 ^|^"%grepcmd% ^'\.3gppnetwork\.org$^'') do set test3gpp=%%r
if NOT "x%test3gpppub%" == "x" (
  set validate_3gppnetwork_realm=%1
) else ( 
  if "x%test3gpp%" == "x" (
    set validate_3gppnetwork_realm=%1
  ) else (
    for /f "delims=" %%r in ('^"%echocmd% %1 ^|^"%sedcmd% -E ^'s/^^^(.*^)^(\.3gppnetwork\.org^)$/\1\.pub\2/g^'') do set validate_3gppnetwork_realm=%%r
  )
)
set %2=%validate_3gppnetwork_realm%
exit /b


:FUNC_validate_port
for /f "delims=" %%r in ('^"%echocmd% %1 ^|^"%trcmd% -d ^'\s\042\n\t\r\^'^'') do set validate_port=%%r
for /f "delims=" %%r in ('^"%echocmd% %validate_port% ^|^"%grepcmd% -E ^'^[0-9]+$^'') do set validate_port=%%r
set %2=%validate_port%
exit /b


:FUNC_dig_it_srv
for /f "delims=" %%k in ('^"%digcmd% +short srv %1 ^|%sortcmd%^" -n -k1 ') do (
  set line=%%k
  for /f "tokens=3,4 delims= " %%l in ("!line!") do (
    call :FUNC_validate_port %%l line_srv_port
    call :FUNC_validate_host %%m line_srv_host
    for /f "delims=" %%z in ('^"%echocmd% !line_srv_host! ^|%sedcmd%^" -E ^'s/^(.*^)\.$/\1/g^'') do set line_srv_host=%%z
  )
  IF NOT "x!line_srv_host!" == "x" (
     IF "x!line_srv_port!" == "x" set line_srv_port=2083
     set srv_host_line=\thost !line_srv_host!:!line_srv_port!\n
  )
  IF "x!host_line!" == "x" ( set host_line=!srv_host_line! ) else ( set host_line=!host_line!!srv_host_line! )
)
set %2=%host_line%
exit /b


:FUNC_dig_it_naptr
for /f "delims=" %%r in ('^"%digcmd% +short naptr %1 ^|%grepcmd% %NAPTR_PATTERN% ^|%sortcmd%^" -n -k1 ') do (
  set line=%%r
  for /f "tokens=3,6 delims= " %%t in ("!line!") do (
    IF x%%t == x"s" set line_srv_token=%%u
    IF x%%t == x"S" set line_srv_token=%%u
  )
  call :FUNC_validate_host !line_srv_token! SRV_HOST
  IF NOT "x!SRV_HOST!" == "x" (
    call :FUNC_dig_it_srv !SRV_HOST! srv_host_line
    IF "x!SERVERS!" == "x" ( set SERVERS=!srv_host_line! ) else ( set SERVERS=!SERVERS!!srv_host_line! )
  )
)
exit /b


REM No server found.
:end
exit 10
