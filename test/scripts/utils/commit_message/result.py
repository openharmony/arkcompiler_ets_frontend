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

Description: utils for test suite
"""

import json
import os


def generate_html_table(data):
    table_rows = ""
    for project, items in data.items():
        for item_idx, item in enumerate(items):
            if item_idx == 0:
                table_rows = ''.join([table_rows, f"<tr><td rowspan='{len(items)}'>{project}</td>"])
            else:
                table_rows = ''.join([table_rows, "<tr>"])

            if item['committer'] is None:
                table_rows = ''.join([table_rows, f"<td colspan=4 style='color: #FF9671;'>{item['title']}</td>"])
            else:
                table_rows = ''.join([table_rows, f"<td>{item['title']}</td>"])
                table_rows = ''.join([table_rows, f"<td>{item['committer']}</td>"])
                table_rows = ''.join([table_rows, f"<td>{item['commit_time_str']}</td>"])
                table_rows = ''.join([table_rows, f"<td><a href='https://gitee.com/{item['pr_link']}'>点击查看</a></td></tr>\n"])

    return table_rows


def get_table_style():
    table_style = f"""
    <style>
            .table-wrapper {{
                width: 1800px;
                margin: auto;
            }}
            .table-container {{
                height: 200px;
                font-family: Arial, sans-serif;
            }}
            .commit-table {{
                border-collapse: collapse;
                border-spacing: 0;
                width: 100%;
                border: 1px solid #ddd;
            }}
            .commit-table th, td {{
                padding: 8px;
                text-align: left;
                border: 1px solid #ddd;
            }}
            .commit-table th {{
                background-color: #f2f2f2;
                color: #333;
                font-weight: bold;
                border-bottom: 1px solid #ddd;
            }}
            .commit-table td {{
                background-color: #fff;
                color: #333;
                vertical-align: middle;
                border-bottom: 1px solid #ddd;
            }}
            .commit-table tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            .commit-table a {{
                color: #0066cc;
                text-decoration: none;
            }}
            caption {{
                font-size: 1.4em;
                font-weight: bold;
                margin-bottom: 18px;
            }}
        </style>
        """

    return table_style


def render_html(data):
    table_rows = generate_html_table(data)
    table_style = get_table_style()
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>提交记录</title>
        {table_style}
    </head>
    <body>
    <div class="table-wrapper">
        <div class="table-container">
            <table class="commit-table">
                <thead>
                <caption>提交记录</caption>
                <tr>
                    <th>仓库</th>
                    <th>描述</th>
                    <th>作者</th>
                    <th>时间</th>
                    <th>链接</th>
                </tr>
                </thead>
                <tbody>
                {table_rows}
                </tbody>
            </table>
        </div>
    </div>

    </body>
    </html>
    """

    return html


def get_result():
    data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.txt')
    with open(data_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    data = {}
    for line in lines:
        item = json.loads(line)

        repo_name = item['repo_name']
        if repo_name in data:
            data[repo_name].append(item)
        else:
            data[repo_name] = [item]

    html = render_html(data)

    commit_log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'commit_log.html')
    with open(commit_log_file, 'w', encoding='utf-8') as file:
        file.write(html)


if __name__ == '__main__':
    get_result()