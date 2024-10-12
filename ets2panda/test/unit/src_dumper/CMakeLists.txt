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

set(SRC_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")
set(COMPILED_DIR "${CMAKE_CURRENT_BINARY_DIR}/compiled")
make_directory(${SRC_DIR})
make_directory(${COMPILED_DIR})

set(DUMPER_TESTS
    ${ES2PANDA_PATH}/test/runtime/ets/OptionalChains.sts
    ${ES2PANDA_PATH}/test/runtime/ets/AccessFannkuch.sts
    ${ES2PANDA_PATH}/test/runtime/ets/DeclareFunction.sts
    ${ES2PANDA_PATH}/test/runtime/ets/Override-1.sts
    ${ES2PANDA_PATH}/test/runtime/ets/TypeInferObject1.sts
)

add_custom_target(test-src-dumper)
add_dependencies(es2panda_tests test-src-dumper)

function(add_test_src_dumper_target FILE_PATH)

    get_filename_component(FILE_NAME "${FILE_PATH}" NAME)
    get_filename_component(FILE_NAME_WE "${FILE_PATH}" NAME_WE)

    set(NEW_TARGET_NAME test-src-dumper-${FILE_NAME_WE})

    string(REGEX REPLACE "[^a-zA-Z0-9_-]" "_" NEW_TARGET_NAME ${NEW_TARGET_NAME})

    add_custom_target(${NEW_TARGET_NAME}
        COMMENT "Dumping and compiling dumped: ${FILE_NAME}"

        COMMAND cp -rf ${FILE_PATH} ${SRC_DIR}/${FILE_NAME}

        COMMAND ${CMAKE_COMMAND} -E env
            ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda>
            --dump-ets-src-after-phases plugins-after-parse --output "${COMPILED_DIR}/${FILE_NAME_WE}.abc"
            "${FILE_PATH}" > "${SRC_DIR}/${FILE_NAME_WE}_dumped.sts"

        COMMAND sed -i '1d' "${SRC_DIR}/${FILE_NAME_WE}_dumped.sts"

        COMMAND ${CMAKE_COMMAND} -E env
            ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda>
            --output "${COMPILED_DIR}/${FILE_NAME_WE}_dumped.abc"
            "${SRC_DIR}/${FILE_NAME_WE}_dumped.sts"
    )

    add_dependencies(${NEW_TARGET_NAME} es2panda)
    add_dependencies(test-src-dumper ${NEW_TARGET_NAME})

endfunction()


foreach(TEST_PATH IN LISTS DUMPER_TESTS)
    add_test_src_dumper_target(${TEST_PATH})
endforeach()
