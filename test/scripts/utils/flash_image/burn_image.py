#!/usr/bin/env python3
# coding: utf-8

"""
Copyright (c) 2024 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in awriting, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import stat
import subprocess
import time
import zipfile

import requests
import yaml
from pywinauto import Application
from tqdm import tqdm


def job(cmd):
    subprocess.run(cmd, shell=False)


def get_tool():
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../config.yaml')
    with open(config_file_path, 'r') as config_file:
        data = yaml.safe_load(config_file.read())
    url = data['url_tools']
    print(f"Getting RKDevTool from {url}")
    r = requests.get(url, stream=True)
    total = int(r.headers.get('content-length'), 0)
    flags = os.O_WRONLY | os.O_CREAT
    modes = stat.S_IWUSR | stat.S_IRUSR

    with os.fdopen(os.open(r".\RKDevTool.zip", flags, modes), "wb") as f, tqdm(
            desc="RKDevTool.zip",
            total=total,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
    ) as bar:
        for byte in r.iter_content(chunk_size=1024):
            size = f.write(byte)
            bar.update(size)
    with zipfile.ZipFile(".\\RKDevTool.zip", 'r') as zfile:
        zfile.extractall(path=".\\RKDevTool")

    os.remove('./RKDevtool.zip')


def end_burn(dlg):
    timeout = 300
    while True:
        if timeout < 0:
            return
        mode = dlg.window(control_type="Tab").window_text()
        if mode == 'Found One MASKROM Device':
            dlg.Button16.click()
            print("image burnning finished")
            return
        else:
            print("please wait for a while...")
            time.sleep(5)
            timeout -= 5


def auto_burn():
    rk_tool_exe_path = os.path.join(os.path.abspath(__file__), r'..\RKDevTool')
    if not os.path.exists(rk_tool_exe_path):
        get_tool()
    os.chdir(rk_tool_exe_path)
    job('hdc shell reboot bootloader')
    app = Application(backend='uia').start('RKDevTool.exe')
    dlg = app.top_window()

    while True:
        mode = dlg.window(control_type="Tab").window_text()
        if mode == 'Found One LOADER Device':
            print('start burning')
            dlg.window(title="Run").click()
            time.sleep(100)
            end_burn(dlg)
            return
        else:
            time.sleep(1)


if __name__ == '__main__':
    auto_burn()