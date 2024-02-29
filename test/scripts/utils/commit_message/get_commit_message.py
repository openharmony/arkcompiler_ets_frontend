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
import argparse
import json
import os
import stat
import time as times
from datetime import datetime, timedelta, time

import requests
import yaml
from lxml import etree

from result import get_result


def parse_config():
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../config.yaml')
    with open(config_file_path, 'r', encoding='utf-8') as config_file:
        configs = yaml.safe_load(config_file)
    return configs


def get_url(name, page):
    url_prefix = 'https://gitee.com/openharmony/'
    url_suffix = f'/pulls?assignee_id=&author_id=&label_ids=&label_text=&milestone_id=&page={page}' \
                 f'&priority=&project_type=&scope=&search=&single_label_id=&single_label_text=&' \
                 f'sort=created_at+desc&status=merged&target_project=&tester_id='
    url = url_prefix + name + url_suffix

    return url


def get_html(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                      ' (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.text
    except Exception:
        print("Failed to request the page")
        return ''
    return ''


def write_data(repo_name, data_file, title, committer, commit_time_str, pr_link):
    data = {
        'repo_name': repo_name,
        'title': title,
        'committer': committer,
        'commit_time_str': commit_time_str,
        'pr_link': pr_link
    }
    flags = os.O_WRONLY | os.O_CREAT
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(data_file, flags, mode), 'a', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False)
        file.write('\n')


def get_commit_records(repo_name, commit_start_time, commit_end_time):
    data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.txt')
    current_data_count = 0
    page = 1
    is_continue = True
    while is_continue:
        url = get_url(repo_name, str(page))
        html = get_html(url)
        tree = etree.HTML(html)
        commit_list = tree.xpath('/html/body/div[2]/div[2]/div[2]/div[2]/div')
        if not commit_list:
            break
        for commit_task in commit_list:
            title = commit_task.xpath('.//div[1]/a/text()')[0]
            committer = commit_task.xpath('.//div[3]/span[2]/a/span/text()')[0]
            commit_time_str = commit_task.xpath('.//div[3]/span[4]/span/text()')[0].strip()
            pr_link = commit_task.xpath('.//div[1]/a/@href')[0]
            commit_time = datetime.strptime(commit_time_str, '%Y-%m-%d %H:%M')
            if commit_start_time <= commit_time <= commit_end_time:
                current_data_count = current_data_count + 1
                write_data(repo_name, data_file, title, committer, commit_time_str, pr_link)
            if commit_time < commit_start_time:
                is_continue = False
        page += 1

    if current_data_count == 0:
        print(f"repo {repo_name} no commit records were found within the specified time range")
        failed_message = (f'this repo has no commit record from {commit_start_time}'
                          f' to {commit_end_time.strftime("%Y-%m-%d %H:%M:%S")}')
        write_data(repo_name, data_file, failed_message, None, None, None)

    return current_data_count


def retry_after_crawl_failed(repo_list, commit_start_time, commit_end_time):
    max_retries = 5
    try_in = 2 * 60
    data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.txt')
    if os.path.exists(data_file):
        os.remove(data_file)
    for i in range(max_retries):
        try:
            data_count = 0
            for repo_name in repo_list:
                current_data_count = get_commit_records(repo_name, commit_start_time, commit_end_time)
                data_count = data_count + current_data_count
            print(f'The data was successfully obtained, a total of {data_count} commit records were retrieved')
            print(f'Data statistics from {commit_start_time} to {commit_end_time.strftime("%Y-%m-%d %H:%M:%S")}'
                  f' were successfully retrieved')
            return True
        except Exception:
            print(f"get data failed! retrying... ({i + 1}/{max_retries})")
            times.sleep(try_in)

    return False


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--startTime', type=str, dest='start_time', default=None,
                        help='specify crawl start time')
    parser.add_argument('--commitRepo', type=str, dest='commit_repo', default=None,
                        nargs='+',
                        help='get commit message in those repos')
    return parser.parse_args()


def clean_log():
    commit_log_html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    'commit_log.html')
    if os.path.exists(commit_log_html_path):
        os.remove(commit_log_html_path)


def run():
    clean_log()
    repo_list_configs = parse_config()
    end_time = datetime.now()
    yesterday = datetime.now() - timedelta(days=1)
    start_time = datetime(yesterday.year, yesterday.month, yesterday.day, 0, 0, 0)
    repo_list = repo_list_configs.get('repo_list')

    arguments = parse_args()
    commit_start_time = repo_list_configs.get('commit_start_time') if arguments.start_time is None \
        else arguments.start_time
    if commit_start_time is not None:
        time_str = datetime.strptime(commit_start_time, '%Y-%m-%d')
        start_time = datetime.combine(time_str, time.min)
        end_time = start_time + timedelta(days=1)

    success = retry_after_crawl_failed(repo_list, start_time, end_time)
    if not success:
        print("Maximum retries reached, failed to crawl the data")
    else:
        get_result()


if __name__ == '__main__':
    run()