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

import json
import logging
import os
import shutil
import time
import subprocess
import sys

import gzip
from PIL import Image


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


def is_file_timestamps_same(file_a, file_b):
    file_a_mtime = os.stat(file_a).st_mtime
    file_b_mtime = os.stat(file_b).st_mtime
    return file_a_mtime == file_b_mtime


def add_executable_permission(file_path):
    current_mode = os.stat(file_path).st_mode
    new_mode = current_mode | 0o111
    os.chmod(file_path, new_mode)


def run_cmd(cmd):
    subprocess.run(cmd, shell=False)


def get_running_screenshot(task, image_name):
    run_cmd(['hdc', 'shell', 'power-shell', 'wakeup;power-shell', 'setmode 602'])
    run_cmd(['hdc', 'shell', 'uinput', '-T', '-m', '420', '1000', '420',
             '400;uinput', '-T', '-m', '420', '400', '420', '1000'])

    build_path = os.path.join(task.path, *task.build_path)
    out_path = os.path.join(build_path, *task.output_hap_path_signed)

    run_cmd(['hdc', 'install', f'{out_path}'])
    run_cmd(['hdc', 'shell', 'aa', 'start', '-a', f'{task.ability_name}', '-b', f'{task.bundle_name}'])
    time.sleep(3)

    screen_path = f'/data/local/tmp/{image_name}.jpeg'
    run_cmd(['hdc', 'shell', 'snapshot_display', '-f', f'{screen_path}'])
    time.sleep(3)

    run_cmd(['hdc', 'file', 'recv', f'{screen_path}', f'{image_name}.jpeg'])
    run_cmd(['hdc', 'shell', 'aa', 'force-stop', f'{task.bundle_name}'])
    run_cmd(['hdc', 'shell', 'bm', 'uninstall', '-n', f'{task.bundle_name}'])

    pic_save_dic = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pictures')
    if not os.path.exists(pic_save_dic):
        os.mkdir(pic_save_dic)

    pic_save_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f'pictures\{task.name}')
    if not os.path.exists(pic_save_path):
        os.mkdir(pic_save_path)

    shutil.move(f'{image_name}.jpeg', pic_save_path)


def compare_screenshot(runtime_picture_path, picture_reference_path, threshold=0.95):
    try:
        runtime_picture = Image.open(runtime_picture_path).convert('RGB')
        picture_reference_path = Image.open(picture_reference_path).convert('RGB')
    except Exception:
        logging.error(f'open image {runtime_picture_path} failed')
        return False
    runtime_picture.thumbnail((256, 256))
    picture_reference_path.thumbnail((256, 256))

    runtime_pixel = runtime_picture.load()
    reference_pixel = picture_reference_path.load()
    width, height = runtime_picture.size

    similar_pixels = 0
    total_pixels = width * height

    for x in range(width):
        for y in range(height):
            if runtime_pixel[x, y] == reference_pixel[x, y]:
                similar_pixels += 1

    similarity = similar_pixels / total_pixels

    if similarity >= threshold:
        return True
    else:
        return False


def verify_runtime(task, picture_name):
    pic_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            f'pictures/{task.name}/{picture_name}.jpeg')
    pic_path_reference = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      f'pictures_reference/{task.name}/{picture_name}.jpeg')
    passed = compare_screenshot(pic_path, pic_path_reference, threshold=0.95)
    if not passed:
        logging.error(f'{task.name} get error when running')
        return False
    return True