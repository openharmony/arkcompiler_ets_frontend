<<<<<<< HEAD
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

import functools
import os
import smtplib
import socket
import traceback
from email.message import EmailMessage

import yaml


def catch_exceptions(cancel_on_failure=False):
    def catch_exceptions_decorator(job_func):
        @functools.wraps(job_func)
        def wrapper(*args, **kwargs):
            try:
                job_func(*args, **kwargs)
            except socket.gaierror:
                print(traceback.format_exc())
        return wrapper
    return catch_exceptions_decorator


def add_content(content, file_name, test_part):
    if file_name == "":
        content += f'<p style="text-align:center;color:red;font-size:25px"> {test_part} not complete yet </p>'
        return content
    if not os.path.exists(file_name):
        content += f'<p style="text-align:center;color:red;font-size:25px"> {test_part} run failed </p>'
        return content
    with open(file_name, 'r') as f:
            content += f.read()
            return content
            
   
def add_attachment(msg, file_list):
    for file in file_list:
        if os.path.exists(file):
            with open(file, 'r') as f:
                msg.add_attachment(f.read(), 'html', filename=os.path.basename(file))        


@catch_exceptions(cancel_on_failure=False)
def send_email():
    yl = open(r".\email_config.yaml", 'r')
    data = yaml.safe_load(yl.read())
    sender = data["sender_email_address"]
    auth_code = data["auth_code"]
    receiver = data["receiver_list"]
    xts_test = data["xts_report_file"]
    sdk_test = data["sdk_report_file"]
    pref_test = data["pref_report_file"]
    attachment_files = data["attatchment_files"]
    yl.close()
    
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = ", ".join(receiver)
    msg['Subject'] = "Arkcompiler Test"
    
    html = ""
    html = add_content(html, xts_test, "xts_test")
    html += '<hr align="center" width="80%" color="gray" size="8">'
    html = add_content(html, sdk_test, "sdk_test")
    html += '<hr align="center" width="80%" color="gray" size="8">'
    html = add_content(html, pref_test, "pref_test")
    msg.add_related(html, "html")

    add_attachment(msg, attachment_files)
    
    smtp_server = 'smtp.163.com'
    smtp = smtplib.SMTP(smtp_server, 25)
    smtp.login(sender, auth_code)
    smtp.sendmail(sender, receiver, msg.as_string())
    smtp.quit()


if __name__ == "__main__":
=======
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

import functools
import os
import smtplib
from email.message import EmailMessage

import yaml


def catch_exceptions(cancel_on_failure=False):
    def catch_exceptions_decorator(job_func):
        @functools.wraps(job_func)
        def wrapper(*args, **kwargs):
            try:
                return job_func(*args, **kwargs)
            except:
                import traceback
                print(traceback.format_exc())
                if cancel_on_failure:
                    return schedule.CancelJob
        return wrapper
    return catch_exceptions_decorator


def add_content(content, file_name, test_part):
    if file_name == "":
        content += f'<p style="text-align:center;color:red;font-size:25px"> {test_part} not complete yet </p>'
        return content
    if not os.path.exists(file_name):
        content += f'<p style="text-align:center;color:red;font-size:25px"> {test_part} run failed </p>'
        return content
    with open(file_name, 'r') as f:
            content += f.read()
            return content
            
   
def add_attachment(msg, file_list):
    for file in file_list:
        if os.path.exists(file):
            with open(file, 'r') as f:
                msg.add_attachment(f.read(), 'html', filename=os.path.basename(file))        


@catch_exceptions(cancel_on_failure=False)
def send_email():
    yl = open(r".\email_config.yaml", 'r')
    data = yaml.safe_load(yl.read())
    sender = data["sender_email_address"]
    auth_code = data["auth_code"]
    receiver = data["receiver_list"]
    xts_test = data["xts_report_file"]
    sdk_test = data["sdk_report_file"]
    pref_test = data["pref_report_file"]
    attachment_files = data["attatchment_files"]
    yl.close()
    
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = ", ".join(receiver)
    msg['Subject'] = "Arkcompiler Test"
    
    html = ""
    html = add_content(html, xts_test, "xts_test")
    html += '<hr align="center" width="80%" color="gray" size="8">'
    html = add_content(html, sdk_test, "sdk_test")
    html += '<hr align="center" width="80%" color="gray" size="8">'
    html = add_content(html, pref_test, "pref_test")
    msg.add_related(html, "html")

    add_attachment(msg, attachment_files)
    
    smtp_server = 'smtp.163.com'
    smtp = smtplib.SMTP(smtp_server, 25)
    smtp.login(sender, auth_code)
    smtp.sendmail(sender, receiver, msg.as_string())
    smtp.quit()


if __name__ == "__main__":
>>>>>>> 55f009a710dbf8276af9c1651b001c475c71ba11
    send_email()