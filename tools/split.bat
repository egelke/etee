@echo off
rem
rem This file is part of .Net ETEE for eHealth.
rem 
rem .Net ETEE for eHealth is free software: you can redistribute it and/or modify
rem it under the terms of the GNU Lesser General Public License as published by
rem the Free Software Foundation, either version 3 of the License, or
rem (at your option) any later version.
rem 
rem .Net ETEE for eHealth  is distributed in the hope that it will be useful,
rem but WITHOUT ANY WARRANTY; without even the implied warranty of
rem MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
rem GNU Lesser General Public License for more details.
rem
rem You should have received a copy of the GNU Lesser General Public License
rem along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

SETLOCAL ENABLEDELAYEDEXPANSION

rem check usage
if "x%1"=="x" goto usage
if "x%2"=="x" goto usage

rem Check to find openssl
set OSSL=

echo.
echo Detecting openssl (version)
%OSSL%openssl version
if ERRORLEVEL 0 goto start
echo Openssl, not found.  Looking in default dir

set OSSL=C:\OpenSSL-Win32\

echo Detecting openssl (again)
%OSSL%openssl version 
if ERRORLEVEL 9009 goto nossl

:start

if not exist %1 goto notfound

set pth=%~d1%~p1

echo.
echo Convert p12 to text format
%OSSL%openssl pkcs12 -in %~1 -passin pass:%2 -passout pass:%2 -out "%pth%export.txt" >> log.txt 2>&1
if ERRORLEVEL 1 goto notOpen
echo Done

echo.
echo Looking for entries
echo. > "%pth%certs.chain"
FOR /F "delims=: tokens=1,2" %%i in (%pth%export.txt) do (
	set i2=%%i%
	set i2=!i2: =!
	set j2=%%j%
	set j2=!j2: =!
	if "!i2!" == "friendlyName" (
		set name=!j2!
	)
	if "%%i" == "-----BEGIN ENCRYPTED PRIVATE KEY-----" (
		echo 	Found key: !name!
		echo. > "%pth%!name!.key"
		set key=true
	)
	if !key! == true (
		echo %%i >> "%pth%!name!.key"	
	)
	if "%%i" == "-----END ENCRYPTED PRIVATE KEY-----" (
		set key=false
	)
	if "%%i" == "-----BEGIN CERTIFICATE-----" (
		echo 	Found certificate: !name!
		set cert=true
	)
	if !cert! == true (
		echo %%i >> "%pth%certs.chain"	
	)
	if "%%i" == "-----END CERTIFICATE-----" (
		set cert=false
	)
)
del "%pth%export.txt"

echo.
echo Creating new p12 files
for %%i in (%pth%*.key) do (
	set file=%pth%%~n1_%%~ni.p12
	echo 	Creating file !file!
	%OSSL%openssl pkcs12 -export -in "%pth%certs.chain" -inkey %%i -out "!file!" -passin pass:%2 -passout pass:%2 -name %%~ni >> log.txt 2>&1
	del "%%i"
)
del "%pth%certs.chain"

echo.
echo DONE, yeeha

goto end

:usage
echo.
echo Usage: "split <<file.p12>> <<password>>"
goto end

:nossl
echo.
echo ERROR: OpenSSL not found
echo Download from http://www.slproweb.com/products/Win32OpenSSL.html (use default dir)
goto end

:notfound
echo.
echo ERROR: file "%1" isn't found
echo Please specify the correct filename of the p12 file 
goto end

:notOpen
echo.
echo ERROR: could not open "%1" with pwd "%2"
echo Verify that the password is correct
goto end

:end