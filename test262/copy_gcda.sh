#!/bin/bash
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
SCRIPT_DIR=$(cd $(dirname $0);pwd)

if [ $# -eq 0 ];
then
    GCDA_PATH=${SCRIPT_DIR%/*}
    GCDA_PATH=${GCDA_PATH%/*}
    GCDA_PATH=${GCDA_PATH%/*}
    GCDA_FILE_PATH="/out/"
    FINAL_GCDA_PATH=$GCDA_PATH$GCDA_FILE_PATH
    ETS_FRONTEND=${SCRIPT_DIR%/*}
    TEXT_NAME="/out/lcov_all"
    TEXT_NAME_DIR=$ETS_FRONTEND$TEXT_NAME
    mkdir -p $TEXT_NAME_DIR
    TEXT_NAME=$TEXT_NAME_DIR/file_name.txt
    find $FINAL_GCDA_PATH -name '*.gcda' > $TEXT_NAME
    find $FINAL_GCDA_PATH -name '*.gcno' >> $TEXT_NAME
    for line in $(cat $TEXT_NAME)
    do
        gcda_file_dir=""
        gcda_file_dir=${line#*'out/'}
        gcda_file_dir=$TEXT_NAME_DIR/gcda_file/$gcda_file_dir
        gcda_file_dir=${gcda_file_dir%/*}
        mkdir -p $gcda_file_dir
        cp -rf $line $gcda_file_dir
    done
    # find $FINAL_GCDA_PATH -name '*.gcda' | xargs rm -rf
    chmod +x $SCRIPT_DIR/llvm_gcov.sh
    lcov -d $TEXT_NAME_DIR -o $TEXT_NAME_DIR/cov_oa_all.info -c --gcov-tool $SCRIPT_DIR/llvm_gcov.sh
fi