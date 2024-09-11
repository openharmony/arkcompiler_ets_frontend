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

import argparse
import re
import subprocess
import tarfile
import datetime
import gzip
from urllib.parse import urlparse

import httpx
import json
import os
import requests
import shutil
import stat
import sys
import time
import tqdm
import yaml
import zipfile


def is_windows():
    return sys.platform == 'win32' or sys.platform == 'cygwin'


def is_mac():
    return sys.platform == 'darwin'


def parse_configs():
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../config.yaml')
    with open(config_file_path, 'r', encoding='utf-8') as config_file:
        configs = yaml.safe_load(config_file)
    return configs


def parse_file_name(download_url):
    parsed_url = urlparse(download_url)
    path = parsed_url.path
    file_full_name = path.split("/")[-1]
    file_name = file_full_name.split(".tar.gz")[0]
    return file_name


def convert_to_datetime(date_str):
    date_format = '%Y%m%d%H%M%S'
    date_time = datetime.datetime.strptime(date_str, date_format)
    return date_time


def get_download_url(task_name, image_date):
    image_date = datetime.datetime.now().strftime('%Y%m%d%H%M%S') if image_date is None else \
        datetime.datetime.strptime(image_date, '%Y-%m-%d').strftime('%Y%m%d') + '235959'
    last_hour = (convert_to_datetime(image_date) +
                 datetime.timedelta(hours=-24)).strftime('%Y%m%d%H%M%S')
    url = 'http://ci.openharmony.cn/api/daily_build/build/tasks'
    downnload_job = {
        'pageNum': 1,
        'pageSize': 1000,
        'startTime': '',
        'endTime': '',
        'projectName': 'openharmony',
        'branch': 'master',
        'component': '',
        'deviceLevel': '',
        'hardwareBoard': '',
        'buildStatus': '',
        'buildFailReason': '',
        'testResult': '',
    }
    downnload_job['startTime'] = str(last_hour)
    downnload_job['endTime'] = str(image_date)
    post_result = requests.post(url, json=downnload_job)
    post_data = json.loads(post_result.text)
    download_url_suffix = ''
    for ohos_sdk_list in post_data['data']['dailyBuildVos']:
        try:
            if get_remote_download_name(task_name) in ohos_sdk_list['obsPath']:
                download_url_suffix = ohos_sdk_list['obsPath']
                break
        except BaseException as err:
            print(err)
    download_url = 'http://download.ci.openharmony.cn/' + download_url_suffix
    return download_url


def retry_after_download_failed(download_url, temp_file, temp_file_name, max_retries=3):
    for i in range(max_retries):
        try:
            is_download_success = download(download_url, temp_file, temp_file_name)
            if is_download_success:
                return True
        except Exception as e:
            print(f"download failed! retrying... ({i + 1}/{max_retries})")
            time.sleep(2)
    return False


def download_progress_bar(response, temp, temp_file_name):
    total_length = int(response.headers.get("content-length"))
    with tqdm.tqdm(total=total_length, unit="B", unit_scale=True) as pbar:
        pbar.set_description(temp_file_name)
        chunk_sum = 0
        count = 0
        for chunk in response.iter_bytes():
            temp.write(chunk)
            chunk_sum += len(chunk)
            percentage = chunk_sum / total_length * 100
            while str(percentage).startswith(str(count)):
                count += 1
            pbar.update(len(chunk))


def supports_resume(download_url):
    with httpx.Client() as client:
        response = client.head(download_url)
        return response.headers.get("Accept-Ranges") == "bytes"


def download(download_url, temp_file, temp_file_name):
    existing_size = 0
    if os.path.exists(temp_file):
        existing_size = os.path.getsize(temp_file)

    headers = {}
    if existing_size:
        headers['Range'] = f'bytes={existing_size}-'

    with httpx.Client() as client:
        response = client.head(download_url)
        total_file_size = int(response.headers['Content-Length'])
        free_space = shutil.disk_usage(os.path.dirname(temp_file)).free
        if free_space < total_file_size - existing_size:
            print('Insufficient disk space; download has been halted.')
            return False

        if existing_size >= total_file_size:
            print(f"{temp_file_name} has already been downloaded.")
            return True

        resume_supported = supports_resume(download_url)
        # If the server supports resuming from breakpoints, it will continue to append modifications to the file.
        mode = 'ab' if resume_supported else 'wb'
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if resume_supported else 0)
        file_mode = stat.S_IWUSR | stat.S_IRUSR

        with client.stream('GET', download_url, headers=headers) as response:
            with os.fdopen(os.open(temp_file, flags, file_mode), mode) as temp:
                download_progress_bar(response, temp, temp_file_name)

    return True


def check_gzip_file(file_path):
    try:
        with gzip.open(file_path, 'rb') as gzfile:
            gzfile.read(1)
    except Exception as e:
        print(e)
        return False
    return True


def check_zip_file(file_path):
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                return True
        else:
            return False
    except Exception as e:
        print(e)
        return False
    return True


def get_remote_download_name(task_name):
    if is_windows():
        if 'sdk' in task_name.lower():
            return 'ohos-sdk-full.tar.gz'
        return 'dayu200.tar.gz'
    elif is_mac():
        if 'sdk' in task_name.lower():
            return 'L2-SDK-MAC-FULL.tar.gz'
        return 'dayu200.tar.gz'
    else:
        print('Unsuport platform to get sdk from daily build')
        return ''


def get_api_version(json_path):
    with open(json_path, 'r') as uni:
        uni_cont = uni.read()
        uni_data = json.loads(uni_cont)
        api_version = uni_data['apiVersion']
    return api_version


def copy_to_output_path(file_name, file_path, output_path_list):
    update_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'update.py')
    cmd = ['python', update_file_path]
    if 'sdk' in file_name.lower():
        sdk_temp_file = os.path.join(file_path, 'sdk_temp')
        cmd.extend(['--sdkFilePath', sdk_temp_file])
        cmd.extend(['--sdkOutputPath'])
        for output_path in output_path_list:
            cmd.extend([output_path])

    if 'dayu' in file_name:
        dayu_temp_file = os.path.join(file_path, 'dayu200_xts')
        cmd.extend(['--dayuFilePath', dayu_temp_file])
        cmd.extend(['--dayuOutputPath'])
        for output_path in output_path_list:
            cmd.extend([output_path])
    print(cmd)
    subprocess.run(cmd, shell=False)


def get_the_unzip_file(download_url, save_path):
    download_name = get_remote_download_name(download_url)
    download_temp_file = os.path.join(save_path, download_name)
    if not os.path.exists(save_path):
        os.mkdir(save_path)
    print(f'download {download_name} from {download_url}, please wait!!!')
    success = retry_after_download_failed(download_url, download_temp_file, download_name)
    if not success:
        return False
    if check_gzip_file(download_temp_file):
        with tarfile.open(download_temp_file, 'r:gz') as tar:
            print(f'Unpacking {download_temp_file}')
            if 'dayu' in download_name:
                save_path = os.path.join(save_path, 'dayu200_xts')
            tar.extractall(save_path)
            print(f'Decompression {download_temp_file} completed')
    elif check_zip_file(download_temp_file):
        with zipfile.ZipFile(download_temp_file, 'r') as zip_file:
            print(f'Unpacking {download_temp_file}')
            zip_file.extractall(save_path)
            print(f'Decompression {download_temp_file} completed')
    else:
        print('The downloaded file is not a valid gzip or zip file.')

    if 'sdk' in download_name:
        unpack_sdk_file(save_path)

    return True


def unpack_sdk_file(path):
    sdk_zip_path_list = [path, 'windows']
    if is_mac():
        sdk_zip_path_list = [path, 'sdk',
                             'packages', 'ohos-sdk', 'darwin']
    sdk_floder = os.path.join(path, 'sdk_temp')
    sdk_zip_path = os.path.join(*sdk_zip_path_list)
    for item in os.listdir(sdk_zip_path):
        if item != '.DS_Store':
            print(f'Unpacking {item}')
            with zipfile.ZipFile(os.path.join(sdk_zip_path, item)) as zip_file:
                zip_file.extractall(os.path.join(sdk_floder))
            print(f'Decompression {item} completed')


def get_task_config(file_name):
    configs = parse_configs()
    download_list = configs['download_list']
    for item in download_list:
        if file_name in item['name']:
            url = item['url']
            date = item['date']
            output_path_list = item['output_path_list']
    return url, date, output_path_list


def delete_redundant_files(task_name, file_name, download_save_path, is_save):
    if is_save:
        date_time = re.search(r"\d{8}", file_name).group()
        new_file_path = os.path.join(download_save_path, f'{date_time}-{task_name}')
        if not os.path.exists(new_file_path):
            temp_file_name = 'sdk_temp' if 'sdk' in task_name else 'dayu200_xts'
            temp_file_path = os.path.join(download_save_path, temp_file_name)
            os.rename(temp_file_path, new_file_path)
    subdirs_and_files = [subdir_or_file for subdir_or_file in os.listdir(download_save_path)]
    for subdir_or_file in subdirs_and_files:
        if not subdir_or_file[0].isdigit():
            path = os.path.join(download_save_path, subdir_or_file)
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)


def write_download_url_to_txt(task_name, download_url):
    download_url_txt = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    'download_url.txt')
    flags = os.O_WRONLY | os.O_CREAT
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(download_url_txt, flags, mode), 'a+', encoding='utf-8') as file:
        file.write(f'{task_name}, {download_url}\n')


def get_the_image(task_name, download_url, image_date, output_path_list):
    configs = parse_configs()
    is_save = configs.get('is_save')
    download_save_path = configs.get('download_save_path')
    if download_url == '':
        download_url = get_download_url(task_name, image_date)
        if download_url == 'http://download.ci.openharmony.cn/':
            print('get download url failed')
            return False
    file_name = parse_file_name(download_url)
    if output_path_list is None:
        output_path_list = get_task_config(file_name)[2]
    print(f'output_path_list: {output_path_list}')
    success = get_the_unzip_file(download_url, download_save_path)
    if not success:
        print(f'get {task_name} unzip file failed')
        return False

    copy_to_output_path(file_name, download_save_path, output_path_list)
    delete_redundant_files(task_name, file_name, download_save_path, is_save)
    write_download_url_to_txt(task_name, download_url)

    return True


def clean_download_log():
    download_url_txt = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'download_url.txt')
    if os.path.exists(download_url_txt):
        os.remove(download_url_txt)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdkUrl', type=str, dest='sdk_url', nargs='?', const='', default=None,
                        help='specify which sdk you want to download')
    parser.add_argument('--dayuUrl', type=str, dest='dayu_url', nargs='?', const='', default=None,
                        help='specify which dayu200 you want to download')
    parser.add_argument('--sdkDate', type=str, dest='sdk_date', default=None,
                        help='specify which day you want to download the sdk')
    parser.add_argument('--dayuDate', type=str, dest='dayu_date', default=None,
                        help='specify which day you want to download the dayu')
    parser.add_argument('--sdkPath', type=str, dest='sdk_path', default=None,
                        nargs='+',
                        help='specify where you want to store the sdk')
    parser.add_argument('--dayuPath', type=str, dest='dayu_path', default=None,
                        nargs='+',
                        help='specify where you want to store the dayu200')

    return parser.parse_args()


def main():
    clean_download_log()
    arguments = parse_args()
    if arguments.sdk_url is not None:
        get_the_image('sdk', arguments.sdk_url, arguments.sdk_date, arguments.sdk_path)
    else:
        sdk_config = get_task_config('sdk')
        get_the_image('sdk', sdk_config[0], sdk_config[1], sdk_config[2])
    if arguments.dayu_url is not None:
        get_the_image('dayu', arguments.dayu_url, arguments.dayu_date, arguments.dayu_path)
    else:
        dayu_config = get_task_config('dayu')
        get_the_image('dayu', dayu_config[0], dayu_config[1], dayu_config[2])


if __name__ == '__main__':
    main()