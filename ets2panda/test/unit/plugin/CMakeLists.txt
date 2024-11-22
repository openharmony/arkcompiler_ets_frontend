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

# now plugin tests with sanitizers triggers CI failure, which could not be reproduce locally, will be fixed in future
if (PANDA_ENABLE_ADDRESS_SANITIZER OR PANDA_ENABLE_THREAD_SANITIZER)
    return()
endif()

# how_to_test_mode
set(COMPILE_MODE "COMPILE")
set(RUNTIME_MODE "RUNTIME")
set(EXPECTED_MODE "EXPECTED")

# how_to_compile_mode
set(LIBRARY_PLUGIN "LIB")
set(EXECUTABLE_PLUGIN "EXE")

set(PLUGIN_TESTS
  #"test_name test_sts_file how_to_test_mode plugin_file_extension(c|cpp) how_to_compile_mode"
  "e2p_test_plugin_dump_json compile.sts ${RUNTIME_MODE} c ${LIBRARY_PLUGIN}"
  "e2p_test_plugin_ets_src compile.sts ${RUNTIME_MODE} c ${LIBRARY_PLUGIN}"
  "e2p_test_plugin_ets_benchmark_test compile.sts ${RUNTIME_MODE} cpp ${LIBRARY_PLUGIN}"
  # 20756 "e2p_test_plugin_ets_benchmark_with_checker_func_test compile.sts ${RUNTIME_MODE} cpp ${LIBRARY_PLUGIN}"
  "e2p_test_plugin_ets_node_types compile.sts ${RUNTIME_MODE} c ${LIBRARY_PLUGIN}"
  "e2p_test_plugin_ets_varibles_and_types compile.sts ${RUNTIME_MODE} c ${LIBRARY_PLUGIN}"
  "e2p_test_plugin_change_func runtime_change_func_call.sts ${RUNTIME_MODE} cpp ${LIBRARY_PLUGIN}"
  "e2p_test_plugin compile.sts ${EXPECTED_MODE} c ${LIBRARY_PLUGIN}"
  "e2p_test_plugin_is compile.sts ${EXPECTED_MODE} c ${LIBRARY_PLUGIN}"
  "plugin_proceed_to_state compile.sts ${EXPECTED_MODE} cpp ${EXECUTABLE_PLUGIN}"
  "plugin_proceed_to_state_update_statements compile.sts ${RUNTIME_MODE} cpp ${EXECUTABLE_PLUGIN}"
  "plugin_proceed_to_state_update_statements_lambda compile.sts ${RUNTIME_MODE} cpp ${EXECUTABLE_PLUGIN}"
  "plugin_proceed_to_state_change_func runtime_change_func_call.sts ${RUNTIME_MODE} cpp ${EXECUTABLE_PLUGIN}"
  "plugin_proceed_to_state_change_call_lambda compile.sts ${COMPILE_MODE} cpp ${EXECUTABLE_PLUGIN}"
)

set(RUNTIME_ARGUMENTS
    --boot-panda-files=${PANDA_BINARY_ROOT}/plugins/ets/etsstdlib.abc${EXTRA_BOOT_PANDAFILES}
    --load-runtimes=ets
    --compiler-enable-jit=true
)

set(ENTRY_POINT ETSGLOBAL::main)

foreach(TEST_DATA IN ITEMS ${PLUGIN_TESTS})
    string(REPLACE " " ";" TEST_DATA_ELEM "${TEST_DATA}")
    list(GET TEST_DATA_ELEM 0 TEST_NAME)
    list(GET TEST_DATA_ELEM 3 EXTENSION)
    list(GET TEST_DATA_ELEM 4 PLUGIN_MODE)
    if(${PLUGIN_MODE} STREQUAL ${LIBRARY_PLUGIN})
        panda_add_library(${TEST_NAME} SHARED ${TEST_NAME}.${EXTENSION})
    else()
        panda_add_executable(${TEST_NAME} ${TEST_NAME}.${EXTENSION} OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        panda_add_sanitizers(TARGET ${TEST_NAME} SANITIZERS ${PANDA_SANITIZERS_LIST})
    endif()
    panda_target_include_directories(${TEST_NAME}
        PRIVATE "${ES2PANDA_PATH}"
        PRIVATE ${OUTPUT_DIR}
    )
    panda_target_link_libraries(${TEST_NAME} es2panda-public)
endforeach()

add_custom_target(es2panda-plugin-test)

foreach(TEST_DATA IN ITEMS ${PLUGIN_TESTS})
    string(REPLACE " " ";" TEST_DATA_ELEM "${TEST_DATA}")
    list(GET TEST_DATA_ELEM 0 TEST_NAME)
    list(GET TEST_DATA_ELEM 1 TEST_STS_FILE)
    list(GET TEST_DATA_ELEM 2 TEST_MODE)
    list(GET TEST_DATA_ELEM 4 PLUGIN_MODE)
    if(${PLUGIN_MODE} STREQUAL ${LIBRARY_PLUGIN})
        add_custom_target(es2panda-plugin-test-compile-${TEST_NAME}
            COMMAND ${CMAKE_COMMAND} -E env
                LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda>
                --plugins=${TEST_NAME} --extension=sts --output="${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME}.abc"
                "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_STS_FILE}" > "${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME}.out"
        )
    endif()
    if(${PLUGIN_MODE} STREQUAL ${EXECUTABLE_PLUGIN})
        add_custom_target(es2panda-plugin-test-compile-${TEST_NAME}
            COMMAND ${CMAKE_COMMAND} -E env
                LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX}
                ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME} $<TARGET_FILE:es2panda>
                --extension=sts --output="${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME}.abc"
                "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_STS_FILE}" > "${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME}.out"
        )
    endif()
    add_dependencies(es2panda-plugin-test-compile-${TEST_NAME} es2panda ${TEST_NAME} es2panda-lib)
    if(${TEST_MODE} STREQUAL ${EXPECTED_MODE})
        add_custom_target(es2panda-plugin-test-expected-${TEST_NAME}
            COMMAND ${CMAKE_COMMAND} -E compare_files
                "${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME}.out" "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_NAME}-expected.txt"
        )
        add_dependencies(es2panda-plugin-test-expected-${TEST_NAME} es2panda-plugin-test-compile-${TEST_NAME} es2panda-lib)
        add_dependencies(es2panda-plugin-test es2panda-plugin-test-expected-${TEST_NAME})
    endif()
    if(${TEST_MODE} STREQUAL ${RUNTIME_MODE})
        add_custom_target(es2panda-plugin-test-runtime-${TEST_NAME}
            COMMAND ${CMAKE_COMMAND} -E env
                LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:ark>
                ${RUNTIME_ARGUMENTS} "${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME}.abc" ${ENTRY_POINT}
                > "${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME}-runtime.out"
        )
        add_dependencies(es2panda-plugin-test-runtime-${TEST_NAME} es2panda-plugin-test-compile-${TEST_NAME} ark es2panda-lib)
        add_dependencies(es2panda-plugin-test es2panda-plugin-test-runtime-${TEST_NAME})
    endif()
    if(${TEST_MODE} STREQUAL ${COMPILE_MODE})
        add_dependencies(es2panda-plugin-test es2panda-plugin-test-compile-${TEST_NAME})
    endif()
endforeach()

add_custom_target(update-es2panda-plugin-test-expected)

foreach(TEST_DATA IN ITEMS ${PLUGIN_TESTS})
    string(REPLACE " " ";" TEST_DATA_ELEM "${TEST_DATA}")
    list(GET TEST_DATA_ELEM 0 TEST_NAME)
    list(GET TEST_DATA_ELEM 1 TEST_STS_FILE)
    list(GET TEST_DATA_ELEM 2 TEST_MODE)
    list(GET TEST_DATA_ELEM 4 PLUGIN_MODE)
    if(${TEST_MODE} STREQUAL ${EXPECTED_MODE})
        if(${PLUGIN_MODE} STREQUAL ${LIBRARY_PLUGIN})
            add_custom_target(update-es2panda-plugin-test-expected-${TEST_NAME}
                COMMAND ${CMAKE_COMMAND} -E env
                    LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda>
                    --plugins=${TEST_NAME} --extension=sts "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_STS_FILE}" >
                    "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_NAME}-expected.txt")
        else()
            add_custom_target(update-es2panda-plugin-test-expected-${TEST_NAME}
                COMMAND ${CMAKE_COMMAND} -E env
                    LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX}
                    ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME} $<TARGET_FILE:es2panda>
                    "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_STS_FILE}" >
                    "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_NAME}-expected.txt")
        endif()
        add_dependencies(update-es2panda-plugin-test-expected-${TEST_NAME} es2panda ${TEST_NAME} es2panda-lib)
        add_dependencies(update-es2panda-plugin-test-expected update-es2panda-plugin-test-expected-${TEST_NAME})
    endif()
endforeach()

add_dependencies(es2panda_tests es2panda-plugin-test)
