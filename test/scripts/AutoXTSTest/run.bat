@REM Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

REM change to work directory
cd /d %~dp0

REM get image & XTS testcases
rd /s /q .\dayu200_xts
python .\getResource\spider.py
del  /q .\dayu200_xts.tar.gz

REM load image to rk3568 \todo
hdc shell reboot bootloader
cd windows
python autoburn.py
cd ..

REM run XTStest
timeout /t 15
hdc shell "power-shell setmode 602"
hdc shell "hilog -Q pidoff"
call .\dayu200_xts\suites\acts\run.bat run acts

REM after
