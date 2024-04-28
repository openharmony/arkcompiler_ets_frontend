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

ets2panda_add_gtest(es2panda_public_test
    CPP_SOURCES es2panda_public_test.cpp
)

ets2panda_add_gtest(ast_verifier_short_test
    CPP_SOURCES ast_verifier_short_test.cpp
)

ets2panda_add_gtest(ast_verifier_private_protected_public_access_correct_test
    CPP_SOURCES ast_verifier_private_protected_public_access_correct_test.cpp
)

ets2panda_add_gtest(ast_verifier_private_access_negative_test_1_4
    CPP_SOURCES ast_verifier_private_access_negative_test_1_4.cpp
)

ets2panda_add_gtest(ast_verifier_private_access_negative_test_5_7
    CPP_SOURCES ast_verifier_private_access_negative_test_5_7.cpp
)

ets2panda_add_gtest(ast_verifier_protected_access_correct_test
    CPP_SOURCES ast_verifier_protected_access_correct_test.cpp
)

ets2panda_add_gtest(ast_verifier_protected_access_negative_test_1_3
    CPP_SOURCES ast_verifier_protected_access_negative_test_1_3.cpp
)

ets2panda_add_gtest(ast_verifier_protected_access_negative_test_4_6
    CPP_SOURCES ast_verifier_protected_access_negative_test_4_6.cpp
)

panda_add_library(e2p_test_plugin SHARED e2p_test_plugin.c)
panda_target_include_directories(e2p_test_plugin PRIVATE  "${ES2PANDA_PATH}")
panda_target_link_libraries(e2p_test_plugin es2panda-public)

add_custom_target(es2panda-plugin-test
  COMMENT "Test es2panda plugin functionality"
  COMMAND ${CMAKE_COMMAND} -E env
    LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda> --plugins=e2p_test_plugin
    "${CMAKE_CURRENT_SOURCE_DIR}/t.ets" > "${CMAKE_CURRENT_BINARY_DIR}/plugin_test.out"
  COMMAND ${CMAKE_COMMAND} -E compare_files
    "${CMAKE_CURRENT_BINARY_DIR}/plugin_test.out" "${CMAKE_CURRENT_SOURCE_DIR}/plugin_test.expected.txt"
)

add_dependencies(es2panda-plugin-test es2panda e2p_test_plugin)
add_dependencies(es2panda_tests es2panda-plugin-test)
