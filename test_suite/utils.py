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

import datetime
import gzip
import httpx
import json
import logging
import os
import requests
import shutil
import time
import tqdm
import subprocess
import sys


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
    return 'stage' in hap_type


def get_sdk_url():
    now_time = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    last_hour = (datetime.datetime.now() + datetime.timedelta(hours=-24)).strftime('%Y%m%d%H%M%S')
    url = 'http://ci.openharmony.cn/api/ci-backend/ci-portal/v1/dailybuilds'
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
    downnload_job['endTime'] = str(now_time)
    post_result = requests.post(url, data = downnload_job)
    post_data = json.loads(post_result.text)
    sdk_url_suffix = ''
    for ohos_sdk_list in post_data['result']['dailyBuildVos']:
        try:
            if 'ohos-sdk-full.tar.gz' in ohos_sdk_list['obsPath']:
                sdk_url_suffix = ohos_sdk_list['obsPath']
                break
        except BaseException as err:
            logging.error(err)
    sdk_url = 'http://download.ci.openharmony.cn/' + sdk_url_suffix
    return sdk_url


def npm_install(loader_path):
    npm_path = shutil.which('npm')
    os.chdir(loader_path)
    try:
        result = subprocess.run(f'{npm_path} install --force', check=True, capture_output=True, text=True)
        if result.stderr:
            logging.error(result.stderr)
    except subprocess.CalledProcessError as e:
        logging.exception(e)
        logging.error(f'npm install failed. Please check the local configuration environment.')
        sys.exit(1)
    os.chdir(os.path.dirname(__file__))


def get_api_version(json_path):
    with open(json_path, 'r') as uni:
        uni_cont = uni.read()
        uni_data = json.loads(uni_cont)
        api_version = uni_data['apiVersion']
    return api_version


def check_gzip_file(file_path):
    try:
        with gzip.open(file_path, 'rb') as gzfile:
            gzfile.read(1)
    except (gzip.BadGzipFile, OSError):
        return False
    return True


def is_file_timestamps_same(file_a, file_b):
    file_a_mtime = os.stat(file_a).st_mtime
    file_b_mtime = os.stat(file_b).st_mtime
    return file_a_mtime == file_b_mtime


def download(url, temp_file, temp_file_name):
    with httpx.stream('GET', url) as response:
        with open(temp_file, "wb") as temp:
            total_length = int(response.headers.get("content-length"))
            with tqdm.tqdm(total=total_length, unit="B", unit_scale=True) as pbar:
                pbar.set_description(temp_file_name)
                for chunk in response.iter_bytes():
                    temp.write(chunk)
                    pbar.update(len(chunk))
