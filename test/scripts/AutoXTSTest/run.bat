@echo on

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
start .\dayu200_xts\suites\acts\run.bat run acts

REM after
