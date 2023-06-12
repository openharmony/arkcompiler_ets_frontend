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

Description: prepare environment for test
"""

import logging
import os
import shutil
import validators

import options
from utils import is_linux, is_mac, is_windows, get_time_string

def check_deveco_installation():
    if is_linux():
        return True ## caution! TODO: just for test, should be False
    if is_mac() or (is_windows() and not options.arguments.pack_only):
        if not os.path.exists(options.configs['deveco_path']):
            logging.error("DevEco not found!")
            return False
    return True


def GetSdkFromRemote():
    ## TODO: 1)download sdk, 2)unzip sdk, 3)run npm install in ets and js dir
    return ''


def update_sdk_to_deveco(sdk_path):
    deveco_sdk_path = options.configs['deveco_sdk_path']
    shutil.move(deveco_sdk_path, deveco_sdk_path + '-' + get_time_string())
    for item in os.listdir(sdk_path):
        shutil.move(os.path.join(sdk_path, item), os.path.join(deveco_sdk_path, item))


def prepare_sdk():
    sdk_arg = options.arguments.sdk_path
    if sdk_arg == '':
        return True  # use the sdk specified in config.yaml

    sdk_path = sdk_arg
    if validators.url(sdk_arg):
        sdk_path = GetSdkFromRemote()

    if not os.path.exists(sdk_path):
        return False

    update_sdk_to_deveco(sdk_path)
    return True


def prepare_image():
    if options.arguments.pack_only:
        return True

    ## TODO: 1)download image, 2)flash image

    return True


def prepare_test_env():
    return check_deveco_installation() and prepare_sdk() and prepare_image()
