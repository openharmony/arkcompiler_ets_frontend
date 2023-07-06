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
import sys
import tarfile
import zipfile

import validators

import options
from utils import is_linux, is_mac, is_windows, get_time_string, get_api_version, npm_install, check_gzip_file, download


def setup_env():
    old_env = os.environ.copy()
    old_env_path = old_env['PATH']

    java_home = os.path.join(options.configs.get('deveco_path'), 'jbr')
    node_js_path = options.configs.get('node_js_path')
    java_path = os.path.join(java_home, 'bin')

    os.environ['PATH'] = os.pathsep.join([java_path, node_js_path]) + os.pathsep + old_env_path
    os.environ['JAVA_HOME'] = java_home


def check_deveco_env():
    if is_linux():
        return False

    java_path = os.path.join(options.configs.get('deveco_path'), 'jbr')
    if not os.path.exists(java_path):
        logging.error("Java not found!")
        return False

    if not os.path.exists(options.configs.get('node_js_path')):
        logging.error("Node js not found!")
        return False

    return True


def get_sdk_from_remote(sdk_url):
    deveco_sdk_path = options.configs.get('deveco_sdk_path')
    temp_floder = deveco_sdk_path + '_temp'
    sdk_temp_file = os.path.join(temp_floder, 'ohos-sdk-full.tar.gz')

    if os.path.exists(temp_floder):
        shutil.rmtree(temp_floder)
    os.mkdir(temp_floder)
    download(sdk_url, sdk_temp_file, 'ohos-sdk-full.tar.gz')
    if not check_gzip_file(sdk_temp_file):
        logging.error('The downloaded file is not a valid gzip file.')
        return '', ''
    with tarfile.open(sdk_temp_file, 'r:gz') as tar:
        tar.extractall(temp_floder)

    sdk_floder = os.path.join(temp_floder, 'SDK')
    for item in os.listdir(os.path.join(*[temp_floder, 'ohos-sdk', 'windows'])):
        with zipfile.ZipFile(os.path.join(*[temp_floder, 'ohos-sdk', 'windows', item])) as zip_file:
            zip_file.extractall(os.path.join(sdk_floder))

    if not npm_install(os.path.join(*[sdk_floder, 'ets', 'build-tools', 'ets-loader'])) or \
        not npm_install(os.path.join(*[sdk_floder, 'js', 'build-tools', 'ace-loader'])):
        return '', ''

    api_version = get_api_version(os.path.join(*[sdk_floder, 'ets', 'oh-uni-package.json']))
    return sdk_floder, api_version


def update_sdk_to_deveco(sdk_path, api_version):
    if not api_version:
        api_version = '9'
    deveco_sdk_path = options.configs.get('deveco_sdk_path')
    deveco_sdk_version_path = os.path.join(deveco_sdk_path, api_version)
    if os.path.exists(deveco_sdk_version_path):
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
        sdk_path, api_version = get_sdk_from_remote(sdk_arg)

    if not sdk_path or not os.path.exists(sdk_path):
        return False

    update_sdk_to_deveco(sdk_path, api_version)
    return True


def prepare_image():
    if options.arguments.run_haps:
        return True

    ## TODO: 1)download image, 2)flash image

    return True


def prepare_test_env():
    prepared = check_deveco_env()
    setup_env()
    prepared = prepared and prepare_sdk() and prepare_image()
    return prepared
