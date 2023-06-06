#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
import tarfile
import json
import requests
import xml.etree.ElementTree as ET
from tqdm import tqdm


def get_images_and_testcases(url):
    print(f"Get new image from {url},please wait!")
    r = requests.get(url, stream=True)
    total = int(r.headers.get('content-length'), 0)
    flags = os.WRONLY | os.CREAT | os.EXCL
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(".\\dayu200_xts.tar.gz", flags, modes), "wb") as f, tqdm(
        desc="dayu200_xts.tar.gz",
        total=total,
        unit='iB',
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        for data in r.iter_content(chunk_size=1024):
            size = f.write(data)
            bar.update(size)
    print("extracrting file")
    with tarfile.open(".\\dayu200_xts.tar.gz", "r") as tar:
        for member in tqdm(desc='dayu200_xts', iterable=tar.getmembers(), total=len(tar.getmembers())):
            tar.extract(path=".\\dayu200_xts", member=member)

   
def get_url():
    url = "http://ci.openharmony.cn/api/ci-backend/ci-portal/v1/dailybuilds"
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'POST, GET, PUT, OPTIONS, DELETE, PATCH',
        'Access-Control-Allow-Origin': '*',
        'Connection': 'keep-alive',
        'Content-Length': '216',
        'Content-Type': 'application/json;charset=UTF-8',
        'Cookie': '_frid=d54846f4e88e415587e14aed0e4a9d63;\
         __51vcke__JhI7USZ6OfAHQZUm=0af50c49-e1b6-5ca4-9356-a986a785be93;\
          __51vuft__JhI7USZ6OfAHQZUm=1684307559015;\
           _fr_ssid=c60810a1808f447b9f696d9534294dcb;\
            __51uvsct__JhI7USZ6OfAHQZUm=5;\
             __vtins__JhI7USZ6OfAHQZUm=%7B%22sid%22%3A%20%22972e7520-a952-52ff-b0f4-0c3ca53da01b%22%2C%20%22vd%22%3A%205%2C%20%22stt%22%3A%201947502%2C%20%22dr%22%3A%20409887%2C%20%22expires%22%3A%201684921552594%2C%20%22ct%22%3A%201684919752594%7D;\
              _fr_pvid=3a57d4c932eb4e10814323c8d3758b0d',
        'hide': 'false',
        'Host': 'ci.openharmony.cn',
        'Origin': 'http://ci.openharmony.cn',
        'Referer': 'http://ci.openharmony.cn/dailys/dailybuilds',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64) \
        AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0\
         Safari/537.36 Edg/113.0.1774.50'
    }
    data = {
        'branch': "master",
        'buildFailReason': "",
        'buildStatus': "success",
        'component': "dayu200-arm64",
        'deviceLevel': "",
        'endTime': "",
        'hardwareBoard': "",
        'pageNum': 1,
        'pageSize': 8,
        'projectName': "openharmony",
        'startTime': "",
        'testResult': ""
    }
    response = requests.post(url, json=data, headers=headers)
    json_obj = json.loads(response.text)
    start_time = json_obj['result']['dailyBuildVos'][0]['buildStartTime']
    start_time = start_time[:8] + "_" + start_time[8:]
    return f"http://download.ci.openharmony.cn/version/Daily_Version/dayu200-arm64\
             /{start_time}/version-Daily_Version-dayu200-arm64-{start_time}-dayu200-arm64.tar.gz"


def change_config(xml_path=".\\dayu200_xts\\suites\\acts\\config\\user_config.xml", \
                 xml_dw="./environment/device/port"):
    doc = ET.parse(xml_path)
    root = doc.getroot()
    sub1 = root.find(xml_dw)
    sub1.text = "8710"
    doc.write(xml_path)


if __name__ == '__main__':
    get_images_and_testcases(get_url())
    change_config()