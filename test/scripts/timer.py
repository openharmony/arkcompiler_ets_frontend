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

import os
import subprocess
import time

import schedule

import send_email


def job(path):
    subprocess.run(path, shell=False)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    #do prepare
    schedule.every().day.at("20:00").do(job, path=r'.\auto_xts_test\run.bat').tag('daily_xts_task')
    #do sdk_test
    #do perf_test
    schedule.every().day.at("20:00").do(send_email.send_email).tag("send_email")
    schedule.run_all()
    while True:
        schedule.run_pending()
        time.sleep(1)