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

import httpx
import logging
import os
import shutil
import sys
import tarfile
import tqdm
import validators
import zipfile

import options
from utils import is_linux, is_mac, is_windows, get_time_string, get_api_version, npm_install, check_gzip_file

def check_deveco_installation():
    if is_linux():
        return True ## caution! TODO: just for test, should be False
    if is_mac() or (is_windows() and not options.arguments.pack_only):
        if not os.path.exists(options.configs['deveco_path']):
            logging.error("DevEco not found!")
            return False
    return True


def GetSdkFromRemote(sdk_url):
    deveco_sdk_path = options.configs['deveco_sdk_path']
    temp_floder = deveco_sdk_path + '_temp'
    sdk_floder = os.path.join(temp_floder, 'SDK')
    sdk_temp_file = os.path.join(temp_floder, 'ohos-sdk-full.tar.gz')
    
    if os.path.exists(temp_floder):
        shutil.rmtree(temp_floder)
    os.mkdir(temp_floder)
    with httpx.stream('GET', sdk_url) as response:
        with open(sdk_temp_file, "wb") as sdktemp:
            total_length = int(response.headers.get("content-length"))
            with tqdm.tqdm(total=total_length, unit="B", unit_scale=True) as pbar:
                pbar.set_description('ohos-sdk-full.tar.gz')
                for chunk in response.iter_bytes():
                    sdktemp.write(chunk)
                    pbar.update(len(chunk))
    if not check_gzip_file(sdk_temp_file):
        logging.error('The downloaded file is not a valid gzip file.')
        sys.exit(1)
    with tarfile.open(sdk_temp_file, 'r:gz') as tar:
        tar.extractall(temp_floder)
    for item in os.listdir(os.path.join(*[temp_floder, 'ohos-sdk', 'windows'])):
        with zipfile.ZipFile(os.path.join(os.path.join(*[temp_floder, 'ohos-sdk', 'windows', item]))) as zip:
            zip.extractall(os.path.join(sdk_floder))
    npm_install(os.path.join(*[sdk_floder, 'ets', 'build-tools', 'ets-loader']))
    npm_install(os.path.join(*[sdk_floder, 'js', 'build-tools', 'ace-loader']))
    api_version = get_api_version(os.path.join(*[sdk_floder, 'ets', 'oh-uni-package.json']))
    return sdk_floder, api_version

def update_sdk_to_deveco(sdk_path, api_version):
    if not api_version:
        api_version = '9'
    deveco_sdk_path = options.configs['deveco_sdk_path']
    deveco_sdk_version_path = os.path.join(deveco_sdk_path, api_version)
    shutil.move(deveco_sdk_version_path, deveco_sdk_version_path + '-' + get_time_string())
    for item in os.listdir(sdk_path):
        shutil.move(os.path.join(sdk_path, item), os.path.join(deveco_sdk_version_path, item))


def prepare_sdk():
    sdk_arg = options.arguments.sdk_path
    if sdk_arg == '':
        return True  # use the sdk specified in config.yaml

    api_version = ''
    sdk_path = sdk_arg
    if validators.url(sdk_arg):
        sdk_path, api_version = GetSdkFromRemote(sdk_arg)

    if not os.path.exists(sdk_path):
        return False

    update_sdk_to_deveco(sdk_path, api_version)
    return True


def prepare_image():
    if options.arguments.pack_only:
        return True

    ## TODO: 1)download image, 2)flash image

    return True


def prepare_test_env():
    return check_deveco_installation() and prepare_sdk() and prepare_image()
