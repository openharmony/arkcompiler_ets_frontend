#!/usr/bin/env python3
# coding: utf-8

"""
Copyright (c) 2024 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import asyncio
import json
import os
import shutil
import sys

import yaml


def parse_configs():
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../config.yaml')
    with open(config_file_path, 'r', encoding='utf-8') as config_file:
        configs = yaml.safe_load(config_file)
    return configs


def get_output_path_list(file_name):
    configs = parse_configs()
    download_list = configs['download_list']
    for item in download_list:
        if item['name'] in file_name:
            output_path_list = item['output_path_list']
    return output_path_list


def is_mac():
    return sys.platform == 'darwin'


def get_api_version(json_path):
    with open(json_path, 'r') as uni:
        uni_cont = uni.read()
        uni_data = json.loads(uni_cont)
        api_version = uni_data['apiVersion']
    return api_version


def before_update_sdk(file_path):
    pass


def after_update_sdk(file_path, output_path):
    if is_mac():
        add_executable_permission_for_mac(output_path)
    # modify sdk version while api version is different from your download
    modify_package_json(file_path, output_path)


def add_executable_permission(file_path):
    current_mode = os.stat(file_path).st_mode
    new_mode = current_mode | 0o111
    os.chmod(file_path, new_mode)


def add_executable_permission_for_mac(sdk_path):
    for item in os.listdir(sdk_path):
        if item != '.DS_Store':
            if item == 'toolchains':
                add_executable_permission(
                    os.path.join(sdk_path, item, 'restool'))
                add_executable_permission(
                    os.path.join(sdk_path, item, 'ark_disasm'))
            elif item == 'ets':
                add_executable_permission(os.path.join(sdk_path, item, 'build-tools',
                                                       'ets-loader', 'bin', 'ark', 'build-mac', 'bin', 'es2abc'))
                add_executable_permission(os.path.join(sdk_path, item, 'build-tools',
                                                       'ets-loader', 'bin', 'ark', 'build-mac', 'legacy_api8',
                                                       'bin', 'js2abc'))
            elif item == 'js':
                add_executable_permission(os.path.join(sdk_path, item, 'build-tools',
                                                       'ace-loader', 'bin', 'ark', 'build-mac', 'bin', 'es2abc'))
                add_executable_permission(os.path.join(sdk_path, item, 'build-tools',
                                                       'ace-loader', 'bin', 'ark', 'build-mac', 'legacy_api8',
                                                       'bin', 'js2abc'))


def get_output_path_api_version(output_path):
    api_version = os.path.basename(output_path)
    if api_version == 'openharmony':
        parts = output_path.split(os.sep)
        if len(parts) >= 2:
            filename = parts[-2]
            configs = parse_configs()
            download_list = configs.get('download_list')
            sdk_item = next((item for item in download_list if item.get('name') == 'sdk'), None)
            api_version_file_map = sdk_item.get('api_version_file_name_map') if sdk_item else {}
            api_version = api_version_file_map.get(filename)
        else:
            api_version = None

    return api_version


def modify_package_json(file_path, output_path):
    output_path_version = get_output_path_api_version(output_path)
    if output_path_version is None:
        print('Modify package json failed, Please check your configuration file'
              ' to ensure the mapping between API and file names is correct.')
        return
    api_version = get_api_version(os.path.join(
        *[file_path, 'ets', 'oh-uni-package.json']))
    if output_path_version != api_version:
        for file_name in os.listdir(output_path):
            if file_name == '.DS_Store':
                continue
            package_json_path = os.path.join(output_path, rf'{file_name}/oh-uni-package.json')
            with open(package_json_path, 'r+') as json_file:
                json_file.seek(0)
                data = json.load(json_file)
                data['apiVersion'] = get_output_path_api_version(output_path)
                json_file.seek(0)
                json.dump(data, json_file, indent=2)
                json_file.truncate()


async def update_sdk_to_output_path(file_path, output_path):
    before_update_sdk(file_path)
    await copy_image_async(file_path, output_path)
    after_update_sdk(file_path, output_path)


async def update_dayu_to_output_path(file_path, output_path):
    await copy_image_async(file_path, output_path)


async def copy_image_async(file_path, output_path):
    if os.path.exists(output_path):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, shutil.rmtree, output_path)
    print(f'Copy from {file_path} to {output_path}, please wait!!!')
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, shutil.copytree, file_path, output_path)


async def update_image_async(file_path, output_path, semaphore):
    await semaphore.acquire()
    try:
        update_task_mapping = {
            "sdk": update_sdk_to_output_path,
            "dayu": update_dayu_to_output_path
        }
        for task in update_task_mapping:
            if task in file_path:
                await update_task_mapping[task](file_path, output_path)
                await asyncio.sleep(1)
                print(f'File copied to {output_path} successfully')
                break
    finally:
        semaphore.release()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdkFilePath', type=str, dest='sdk_file_path', default=None,
                        help='specify which sdk image you want to copy')
    parser.add_argument('--sdkOutputPath', type=str, dest='sdk_output_path', default=None,
                        nargs='+',
                        help='specify where you want to store the file')
    parser.add_argument('--dayuFilePath', type=str, dest='dayu_file_path', default=None,
                        help='specify which dayu image you want to copy')
    parser.add_argument('--dayuOutputPath', type=str, dest='dayu_output_path', default=None,
                        nargs='+',
                        help='specify where you want to store the file')

    return parser.parse_args()


async def start_update_image_task(file_path, output_path_list, max_async_tasks=3):
    if output_path_list is None:
        output_path_list = get_output_path_list(file_path)
    semaphore = asyncio.Semaphore(max_async_tasks)
    tasks = [asyncio.create_task(update_image_async(file_path, output_path, semaphore))
             for output_path in output_path_list]

    await asyncio.gather(*tasks)


async def run():
    arguments = parse_args()

    if arguments.sdk_file_path is not None:
        await start_update_image_task(arguments.sdk_file_path, arguments.sdk_output_path)
    if arguments.dayu_file_path is not None:
        await start_update_image_task(arguments.dayu_file_path, arguments.dayu_output_path)
    if arguments.sdk_file_path is None and arguments.dayu_file_path is None:
        print('please input which image you want to copy')
        return


if __name__ == '__main__':
    asyncio.run(run())
