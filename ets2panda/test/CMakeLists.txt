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

# target to test compilation issue on arm32 platforms
# see issue https://gitee.com/openharmony-sig/arkcompiler_ets_frontend/issues/I84VFY
if (PANDA_TARGET_ARM32)
  add_custom_target(ets_tests_arm32_punctuator_any_equal
      COMMAND ${PANDA_ROOT}/tests/tests-u-runner/runner.sh
              --build-dir ${PANDA_BINARY_ROOT}
              --arm32-qemu
              --ets-runtime
              --test-file PunctuatorAnyEqual.ets
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
            SOURCES ${ARG_CPP_SOURCES}
            LIBRARIES
            es2panda-public es2panda-lib
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

if(PANDA_REGRESSION_TESTS)
    panda_add_gtest(
        NAME es2panda_public_test
        SOURCES
            unit/public/es2panda_public_test.cpp
        LIBRARIES
            es2panda-public es2panda-lib arkassembler arkbytecodeopt
        INCLUDE_DIRS
            ${ES2PANDA_ROOT}
        SANITIZERS
            ${PANDA_SANITIZERS_LIST}
          )

    panda_add_library(e2p_test_plugin SHARED unit/public/e2p_test_plugin.c)
    panda_target_include_directories(e2p_test_plugin PRIVATE  "${CMAKE_CURRENT_SOURCE_DIR}/..")
    panda_target_link_libraries(e2p_test_plugin es2panda-public)

    add_custom_target(es2panda-plugin-test
      COMMENT "Test es2panda plugin functionality"
      COMMAND ${CMAKE_COMMAND} -E env
        LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda> --plugins=e2p_test_plugin
        "${CMAKE_CURRENT_SOURCE_DIR}/unit/public/t.ets" > "${CMAKE_CURRENT_BINARY_DIR}/plugin_test.out"
      COMMAND ${CMAKE_COMMAND} -E compare_files
        "${CMAKE_CURRENT_BINARY_DIR}/plugin_test.out" "${CMAKE_CURRENT_SOURCE_DIR}/unit/public/plugin_test.expected.txt"
    )
    add_dependencies(es2panda-plugin-test es2panda e2p_test_plugin)
    add_dependencies(es2panda_tests es2panda-plugin-test)

    ets2panda_add_gtest(es2panda_dynamic_call_test
            CPP_SOURCES unit/dynamic/dynamic_call_test.cpp
    )

    panda_add_gtest(
        NAME es2panda_astverifier_tests
        SOURCES
            unit/public/ast_verifier_test.cpp
        LIBRARIES
            es2panda-public es2panda-lib
        INCLUDE_DIRS
            ${ES2PANDA_PATH}
            ${ES2PANDA_BINARY_ROOT}
        SANITIZERS
            ${PANDA_SANITIZERS_LIST}
    )

    if(PANDA_WITH_ETS)
            panda_add_gtest(
                NAME scopes_initialization_test
                SOURCES
                    unit/lowerings/scopes_initialization.cpp
                LIBRARIES
                    es2panda-lib es2panda-public arkassembler arkbytecodeopt
                INCLUDE_DIRS
                    ${ES2PANDA_PATH}
                    ${OUTPUT_DIR}

                    SANITIZERS
                    ${PANDA_SANITIZERS_LIST}
            )
            panda_add_gtest(
                NAME es2panda_checker_tests
                SOURCES
                    unit/checker_test.cpp
                LIBRARIES
                    es2panda-public es2panda-lib
                INCLUDE_DIRS
                    ${ES2PANDA_ROOT}
                SANITIZERS
                    ${PANDA_SANITIZERS_LIST}
            )

    endif()

    panda_add_gtest(
        NAME es2panda_astdumper_tests
        SOURCES
            unit/ast_dumper_test.cpp
        LIBRARIES
            es2panda-public es2panda-lib arkassembler arkbytecodeopt
        INCLUDE_DIRS
            ${ES2PANDA_PATH}
        SANITIZERS
            ${PANDA_SANITIZERS_LIST}
    )

    panda_add_gtest(
        NAME es2panda_union_normalization_tests
        SOURCES
            unit/union_normalization_test.cpp
        LIBRARIES
            es2panda-public es2panda-lib arkassembler arkbytecodeopt
        INCLUDE_DIRS
            ${ES2PANDA_PATH}
            ${ES2PANDA_BINARY_ROOT}
        SANITIZERS
            ${PANDA_SANITIZERS_LIST}
    )

    add_subdirectory(tsconfig)
endif()

add_subdirectory(options)
