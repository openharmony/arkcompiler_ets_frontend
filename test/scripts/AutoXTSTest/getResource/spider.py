#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import stat
import tarfile
import json
import xml.etree.ElementTree as ET

import requests
from tqdm import tqdm
import yaml


def get_images_and_testcases(url):
    print(f"Get new image from {url},please wait!")
    r = requests.get(url, stream=True)
    total = int(r.headers.get('content-length'), 0)
    flags = os.O_WRONLY | os.O_CREAT 
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(r"D:\AutoXTSTest\dayu200_xts.tar.gz", flags, modes), "wb") as f, tqdm(
        desc="dayu200_xts.tar.gz",
        total=total,
        unit='iB',
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        for byte in r.iter_content(chunk_size=1024):
            size = f.write(byte)
            bar.update(size)
    print("extracrting file")
    with tarfile.open(r"D:\AutoXTSTest\dayu200_xts.tar.gz", "r") as tar:
        for member in tqdm(desc='dayu200_xts', iterable=tar.getmembers(), total=len(tar.getmembers())):
            tar.extract(path=r"D:\AutoXTSTest\dayu200_xts", member=member)

   
def get_url(url, headers, json, url_2):
    response = requests.post(url, json=json, headers=headers)
    json_obj = json.loads(response.text)
    start_time = json_obj['result']['dailyBuildVos'][0]['buildStartTime']
    start_time = start_time[:8] + "_" + start_time[8:]
    return url_2[0] + start_time + url_2[1] + start_time + url_2[2]


def change_config(xml_path=r"D:\AutoXTSTest\dayu200_xts\suites\acts\config\user_config.xml", \
                 xml_dw="./environment/device/port"):
    doc = ET.parse(xml_path)
    root = doc.getroot()
    sub1 = root.find(xml_dw)
    sub1.text = "8710"
    doc.write(xml_path)


if __name__ == '__main__':
    yl = open(r".\getResource\config.yaml", 'r')
    data = yaml.safe_load(yl.read(), Loader=yaml.FullLoader)
    get_images_and_testcases(get_url(data['url'], data['headers'], data['data'], data['url_2']))
    yl.close()
    change_config()