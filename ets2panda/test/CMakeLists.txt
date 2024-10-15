# Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

# target to test compilation issue on arm32 platforms
# see issue https://gitee.com/openharmony-sig/arkcompiler_ets_frontend/issues/I84VFY
if (PANDA_TARGET_ARM32)
  add_custom_target(ets_tests_arm32_punctuator_any_equal
      COMMAND ${PANDA_ROOT}/tests/tests-u-runner/runner.sh
              --build-dir ${PANDA_BINARY_ROOT}
              --arm32-qemu
              --ets-runtime
              --test-file PunctuatorAnyEqual.sts
  )
endif()

# ignore ARM32 because some files (not gnueabi or gnueabihf) are incompatible with 32x processors
# this will be fixed in the future
if(PANDA_TARGET_ARM32 OR PANDA_ARM64_TESTS_WITH_SANITIZER)
    return()
endif()

add_custom_target(es2panda_tests COMMENT "Running es2panda test suites")

function(ets2panda_add_gtest TARGET)
    # Parse arguments
    cmake_parse_arguments(
            ARG
            ""
            ""
            "CPP_SOURCES"
            ${ARGN}
    )

    MESSAGE(${TARGET})

    panda_add_gtest(
            NAME ${TARGET}
            SOURCES
                ${ARG_CPP_SOURCES}
            LIBRARIES
                es2panda-public
                es2panda-lib
                arkassembler
                arkbytecodeopt
            INCLUDE_DIRS
                ${ES2PANDA_PATH}
                ${ES2PANDA_BINARY_ROOT}
            SANITIZERS
                ${PANDA_SANITIZERS_LIST}
    )
endfunction(ets2panda_add_gtest)


if(PANDA_WITH_ETS)
    if (NOT (PANDA_ENABLE_ADDRESS_SANITIZER OR PANDA_ENABLE_THREAD_SANITIZER) OR
        NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR
        PANDA_CI_TESTING_MODE STREQUAL "Nightly")
            set(PANDA_REGRESSION_TESTS 1)
    endif()
endif()

add_subdirectory(tsconfig)
add_subdirectory(options)
add_subdirectory(unit)
