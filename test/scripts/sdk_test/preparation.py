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
import tarfile
import zipfile

import validators

import options
from utils import is_linux, is_mac, get_time_string, add_executable_permission
from utils import get_api_version, check_gzip_file, download, get_remote_sdk_name


def setup_env():
    old_env = os.environ.copy()
    old_env_path = old_env['PATH']

    java_home = os.path.join(options.configs.get('deveco_path'), 'jbr')
    node_js_path = options.configs.get('node_js_path')
    if is_mac():
        node_js_path = os.path.join(node_js_path, 'bin')
    java_path = os.path.join(java_home, 'bin')

    os.environ['PATH'] = os.pathsep.join(
        [java_path, node_js_path]) + os.pathsep + old_env_path
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
    sdk_name = get_remote_sdk_name()
    sdk_zip_path_list = [temp_floder, 'ohos-sdk', 'windows']
    if is_mac():
        sdk_zip_path_list = [temp_floder, 'sdk',
                             'packages', 'ohos-sdk', 'darwin']
    sdk_temp_file = os.path.join(temp_floder, sdk_name)

    if os.path.exists(temp_floder):
        shutil.rmtree(temp_floder)
    os.mkdir(temp_floder)
    download(sdk_url, sdk_temp_file, sdk_name)
    if not check_gzip_file(sdk_temp_file):
        logging.error('The downloaded file is not a valid gzip file.')
        return '', ''
    with tarfile.open(sdk_temp_file, 'r:gz') as tar:
        tar.extractall(temp_floder)

    sdk_floder = os.path.join(temp_floder, 'SDK_TEMP')
    sdk_zip_path = os.path.join(*sdk_zip_path_list)
    for item in os.listdir(sdk_zip_path):
        if item != '.DS_Store':
            logging.info(f'Unpacking {item}')
            with zipfile.ZipFile(os.path.join(sdk_zip_path, item)) as zip_file:
                zip_file.extractall(os.path.join(sdk_floder))
            logging.info(f'Decompression {item} completed')

    api_version = get_api_version(os.path.join(
        *[sdk_floder, 'ets', 'oh-uni-package.json']))
    return sdk_floder, api_version


def update_sdk_to_deveco(sdk_path, api_version):
    deveco_sdk_path = options.configs.get('deveco_sdk_path')
    deveco_sdk_version_path = os.path.join(deveco_sdk_path, api_version)
    for sdk_item in os.listdir(deveco_sdk_path):
        if sdk_item.startswith(f'{api_version}-'):
            shutil.rmtree(os.path.join(deveco_sdk_path, sdk_item))
    if os.path.exists(deveco_sdk_version_path):
        shutil.move(deveco_sdk_version_path,
                    deveco_sdk_version_path + '-' + get_time_string())
    for item in os.listdir(sdk_path):
        if item != '.DS_Store':
            if is_mac():
                if item == 'toolchains':
                    add_executable_permission(
                        os.path.join(sdk_path, item, 'restool'))
                    add_executable_permission(
                        os.path.join(sdk_path, item, 'ark_disasm'))
                elif item == 'ets':
                    add_executable_permission(os.path.join(sdk_path, item, 'build-tools',
                            'ets-loader', 'bin', 'ark', 'build-mac', 'bin', 'es2abc'))
                    add_executable_permission(os.path.join(sdk_path, item, 'build-tools',
                            'ets-loader', 'bin', 'ark', 'build-mac', 'legacy_api8', 'bin', 'js2abc'))
                elif item == 'js':
                    add_executable_permission(os.path.join(sdk_path, item, 'build-tools',
                            'ace-loader', 'bin', 'ark', 'build-mac', 'bin', 'es2abc'))
                    add_executable_permission(os.path.join(sdk_path, item, 'build-tools',
                            'ace-loader', 'bin', 'ark', 'build-mac', 'legacy_api8', 'bin', 'js2abc'))
            shutil.move(os.path.join(sdk_path, item),
                        os.path.join(deveco_sdk_version_path, item))


def prepare_sdk():
    sdk_arg = options.arguments.sdk_path
    if sdk_arg == '':
        return True  # use the sdk specified in config.yaml

    api_version = '9'
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

    # TODO: 1)download image, 2)flash image

    return True


def clean_log():
    output_log_file = options.configs.get('log_file')
    daily_report_file = options.configs.get('output_html_file')
    if os.path.exists(output_log_file):
        os.remove(output_log_file)
    if os.path.exists(daily_report_file):
        os.remove(daily_report_file)


def prepare_test_env():
    clean_log()
    prepared = check_deveco_env()
    setup_env()
    prepared = prepared and prepare_sdk() and prepare_image()
    return prepared
