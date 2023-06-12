#!/usr/bin/env python3
# coding: utf-8

"""
Copyright (c) 2023 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Description: utils for test suite
"""

import logging
import time
import sys
import subprocess

log_level_dict = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warn': logging.WARN,
    'error': logging.ERROR
}

def init_logger(log_level, log_file):
    logging.basicConfig(filename=log_file,
                        level=log_level_dict[log_level],
                        encoding='utf-8',
                        format='[%(asctime)s %(filename)s:%(lineno)d]: [%(levelname)s] %(message)s')


def is_windows():
    return sys.platform == 'win32' or sys.platform == 'cygwin'


def is_mac():
    return sys.platform == 'darwin'


def is_linux():
    return sys.platform == 'linux'


def get_time_string():
    return time.strftime('%Y%m%d-%H%M%S')


def is_esmodule(hap_type):
    # if hap_type is stage, it's esmodule.
    # if hap_type is js, fa, compatible 8, it's js_bundle
    return hap_type in ['stage', 'stage_widget']


def is_same_file(file_a, file_b):
    cmd = []
    if is_windows():
        cmd.append('fc')
    elif is_mac():
        cmd.append('diff')

    cmd.extend([file_a, file_b])
    logging.debug("is_same_file cmd: %s", cmd)
    process = subprocess.Popen(cmd)
    process.communicate()
    ret_code = process.returncode

    return True if ret_code == 0 else False