# Copyright (c) 2024 Huawei Device Co., Ltd.
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

function(add_es2panda_tsconfig_test tsproject)
    set(TSPROJECT_TARGET_NAME es2panda-tsconfig-test-build-${tsproject})
    add_custom_target(${TSPROJECT_TARGET_NAME}
        COMMENT "Testing tsconfig for: ${tsproject}"
        DEPENDS es2panda
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        COMMAND ./test.sh $<TARGET_FILE:es2panda> ${tsproject} '${PANDA_RUN_PREFIX}' '${PANDA_ROOT}'
    )
    add_dependencies(es2panda_tests ${TSPROJECT_TARGET_NAME})
endfunction()

add_es2panda_tsconfig_test(empty-include)
add_es2panda_tsconfig_test(ets)
add_es2panda_tsconfig_test(extends)
add_es2panda_tsconfig_test(include)
add_es2panda_tsconfig_test(paths)
add_es2panda_tsconfig_test(glob-include)
