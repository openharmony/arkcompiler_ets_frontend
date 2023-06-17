#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import time

from pywinauto.application import Application


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


if __name__ == "__main__":
    auto_burn()
        