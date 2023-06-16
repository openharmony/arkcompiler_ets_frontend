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
import smtplib
import socket
from email.message import EmailMessage

import yaml


def add_content(content, file_name, test_part):
    if file_name == "":
        content += f'<p style="text-align:center;color:red;font-size:25px"> {test_part} not complete yet </p>'
        return content
    if not os.path.exists(file_name):
        content += f'<p style="text-align:center;color:red;font-size:25px"> {test_part} run failed </p>'
        return content
    with open(file_name, 'r', encoding='utf-8') as f:
        content += f.read()
        return content


def add_attachment(msg, file_list):
    for file in file_list:
        if os.path.exists(file):
            with open(file, 'r', encoding='utf-8') as f:
                msg.add_attachment(f.read(), 'html', filename=os.path.basename(file))


def send_email():
    yl = open(r".\email_config.yaml", 'r')
    data = yaml.safe_load(yl.read())
    sender = data["sender_email_address"]
    auth_code = data["auth_code"]
    receiver = data["receiver_list"]
    smtp_server = data["smtp_server"]
    smtp_port = data["smtp_port"]
    xts_test = data["xts_report_file"]
    sdk_test = data["sdk_report_file"]
    perf_test = data["perf_report_file"]
    attachment_files = data["attatchment_files"]
    yl.close()

    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = ", ".join(receiver)
    msg['Subject'] = "Arkcompiler Test"

    html = ""
    dividing_line = '<hr align="center" width="80%" color="gray" size="8">'
    html = add_content(html, xts_test, "xts_test")
    html += dividing_line
    html = add_content(html, sdk_test, "sdk_test")
    html += dividing_line
    html = add_content(html, perf_test, "perf_test")
    msg.add_related(html, "html")

    add_attachment(msg, attachment_files)

    smtp = smtplib.SMTP(smtp_server, smtp_port)
    smtp.login(sender, auth_code)
    smtp.sendmail(sender, receiver, msg.as_string())
    smtp.quit()


if __name__ == "__main__":
    send_email()