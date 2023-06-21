@REM Copyright (c) 2023 Huawei Device Co., Ltd.
@REM Licensed under the Apache License, Version 2.0 (the "License");
@REM you may not use this file except in compliance with the License.
@REM You may obtain a copy of the License at
@REM
@REM http://www.apache.org/licenses/LICENSE-2.0
@REM
@REM Unless required by applicable law or agreed to in writing, software
@REM distributed under the License is distributed on an "AS IS" BASIS,
@REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@REM See the License for the specific language governing permissions and
@REM limitations under the License.

@echo off
SETLOCAL ENABLEEXTENSIONS

REM change to work directory
cd /d %~dp0

REM log
echo "------------------------------------------------" >> log.log

REM get tool
if not exist .\RKDevTool (
python .\get_resource\get_tool.py
.\RKDevTool\DriverAssitant_v5.1.1\DriverAssitant_v5.1.1\DriverInstall.exe
del /q .\RKDevTool.zip
)
if not exist .\RKDevTool\RKDevTool.exe (goto ToolError)

REM get image & XTS testcases
set var=D:\AutoXTSTest
if not exist %var% (md %var%)
rd /s /q %var%\dayu200_xts
python .\get_resource\spider.py
del /q %var%\dayu200_xts.tar.gz
if not exist %var%\dayu200_xts\suites (goto ResourceError)

REM load image to rk3568 
hdc shell reboot bootloader
cd RKDevTool
python ..\autoburn.py
cd ..
for /f "tokens=*" %%i in ('hdc list targets') do (set target=%%i)
if "%var%"=="[Empty]" (goto BurnError)

REM run XTStest
timeout /t 15
hdc shell "power-shell setmode 602"
hdc shell "hilog -Q pidoff"
for /f "tokens=1,2 delims==" %%i in (running_modules.txt) do (
if "%%i"=="modules" set value=%%j
)
call %var%\dayu200_xts\suites\acts\run.bat run -l %value%

REM get result
cd /d %~dp0
echo "Successfully excute script" >> log.log
if exist result (rd /s /q result)
md result
python get_result.py
ENDLOCAL
exit

REM error process
: ToolError
echo "Error happens while getting tool" >> log.log
ENDLOCAL
exit

: ResourceError
echo "Error happens while getting dailybuilds resource" >> log.log
ENDLOCAL
exit

: BurnError
echo "Error happens while burnning images" >> log.log
ENDLOCAL
exit