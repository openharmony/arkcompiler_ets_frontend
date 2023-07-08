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
import json
import logging
import os
import shutil
import time
import subprocess
import sys

import gzip
import httpx
import requests
import tqdm


def get_log_level(arg_log_level):
    log_level_dict = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warn': logging.WARN,
        'error': logging.ERROR
    }
    if arg_log_level not in log_level_dict.keys():
        return logging.ERROR  # use error as default log level
    else:
        return log_level_dict[arg_log_level]


def init_logger(log_level, log_file):
    logging.basicConfig(filename=log_file,
                        level=get_log_level(log_level),
                        encoding=get_encoding(),
                        format='[%(asctime)s %(filename)s:%(lineno)d]: [%(levelname)s] %(message)s')
    logging.info("Test command:")
    logging.info(" ".join(sys.argv))


def get_encoding():
    if is_windows():
        return 'utf-8'
    else:
        return sys.getfilesystemencoding()


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
    last_hour = (datetime.datetime.now() +
                 datetime.timedelta(hours=-24)).strftime('%Y%m%d%H%M%S')
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
    post_result = requests.post(url, data=downnload_job)
    post_data = json.loads(post_result.text)
    sdk_url_suffix = ''
    for ohos_sdk_list in post_data['result']['dailyBuildVos']:
        try:
            if get_remote_sdk_name() in ohos_sdk_list['obsPath']:
                sdk_url_suffix = ohos_sdk_list['obsPath']
                break
        except BaseException as err:
            logging.error(err)
    sdk_url = 'http://download.ci.openharmony.cn/' + sdk_url_suffix
    return sdk_url


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
    except Exception as e:
        logging.exception(e)
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
                chunk_sum = 0
                count = 0
                for chunk in response.iter_bytes():
                    temp.write(chunk)
                    chunk_sum += len(chunk)
                    percentage = chunk_sum / total_length * 100
                    while str(percentage).startswith(str(count)):
                        if str(percentage).startswith('100'):
                            logging.info(f'SDK Download Complete {percentage: .1f}%')
                            break
                        else:
                            logging.info(f'SDK Downloading... {percentage: .1f}%')
                        count += 1
                    pbar.update(len(chunk))


def add_executable_permission(file_path):
    current_mode = os.stat(file_path).st_mode
    new_mode = current_mode | 0o111
    os.chmod(file_path, new_mode)


def get_remote_sdk_name():
    if is_windows():
        return 'ohos-sdk-full.tar.gz'
    elif is_mac():
        return 'L2-MAC-SDK-FULL.tar.gz'
    else:
        logging.error('Unsuport platform to get sdk from daily build')
        return ''
