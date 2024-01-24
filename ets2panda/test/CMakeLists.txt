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
              ${PANDA_ROOT}
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

if(NOT DEFINED ES2PANDA_REGRESSION_TESTS_GROUPS)
    set(ES2PANDA_REGRESSION_TESTS_GROUPS 32)
endif()

add_custom_target(es2panda_tests COMMENT "Running es2panda test suites")

if(PANDA_WITH_ETS)
    set(ETS_RESULT_FOLDER ${CMAKE_BINARY_DIR}/tests/es2panda-regression-tests)
    set(OPTIONS --parser
                --processes=1
                --build-dir ${PANDA_BINARY_ROOT}
                --es2panda-timeout=120
                --timeout=120
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

    if(NOT CMAKE_CROSSCOMPILING OR NOT PANDA_TARGET_ARM64 OR PANDA_CI_TESTING_MODE STREQUAL "Nightly")
        add_dependencies(es2panda_tests es2panda-regression-tests)
    endif()

    if(TARGET ets_tests)
        add_dependencies(ets_tests es2panda_tests)
    endif()

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
