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

# ignore ARM32 because some files (not gnueabi or gnueabihf) are incompatible with 32x processors
# this will be fixed in the future
if(PANDA_TARGET_ARM32 OR PANDA_ARM64_TESTS_WITH_SANITIZER)
    return()
endif()

if(NOT DEFINED ES2PANDA_REGRESSION_TESTS_GROUPS)
    set(ES2PANDA_REGRESSION_TESTS_GROUPS 32)
endif()

add_custom_target(es2panda_tests COMMENT "Running es2panda test suites")

if(PANDA_WITH_ETS)
    set(ETS_RESULT_FOLDER ${CMAKE_BINARY_DIR}/tests/es2panda-regression-tests)
    set(OPTIONS --parser
                --processes=1
                --build-dir ${PANDA_BINARY_ROOT}
                --groups ${ES2PANDA_REGRESSION_TESTS_GROUPS})

    if(PANDA_TARGET_ARM64)
        set(OPTIONS --test-list-arch=arm64 ${OPTIONS})
        if(PANDA_QEMU_BUILD)
            set(OPTIONS --arm64-qemu ${OPTIONS})
        endif()
    endif()

    if(PANDA_TARGET_ARM32)
        set(OPTIONS --test-list-arch=arm32 ${OPTIONS})
        if(PANDA_QEMU_BUILD)
            set(OPTIONS --arm32-qemu ${OPTIONS})
        endif()
    endif()

    if(NOT PANDA_WITH_ECMASCRIPT)
        set(OPTIONS --no-js ${OPTIONS})
    endif()

    add_custom_target(es2panda-regression-tests COMMENT "Running es2panda-regression-tests test suites")
    foreach(CURRENT_GROUP RANGE 1 ${ES2PANDA_REGRESSION_TESTS_GROUPS})
        add_custom_target(es2panda-regression-tests-${CURRENT_GROUP}
            DEPENDS ark es2panda verifier
            WORKING_DIRECTORY ${PANDA_ROOT}
            COMMAND ${PANDA_ROOT}/tests/tests-u-runner/runner.sh
                            ${PANDA_ROOT}
                            ${OPTIONS}
                            --work-dir=${ETS_RESULT_FOLDER}/group-${CURRENT_GROUP}
                            --group-number ${CURRENT_GROUP}
        )
        add_dependencies(es2panda-regression-tests es2panda-regression-tests-${CURRENT_GROUP})
    endforeach()

    add_dependencies(es2panda_tests es2panda-regression-tests)
    if(TARGET ets_tests)
        add_dependencies(ets_tests es2panda_tests)
    endif()

    add_subdirectory(tsconfig)
endif()
