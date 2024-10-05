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

ets2panda_add_gtest(ast_builder_test
    CPP_SOURCES ast_builder_test.cpp
)

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

ets2panda_add_gtest(ast_verifier_reference_typeannotation_test
    CPP_SOURCES ast_verifier_reference_typeannotation_test.cpp
)

ets2panda_add_gtest(ast_verifier_identifier_has_variable_test
    CPP_SOURCES ast_verifier_identifier_has_variable_test.cpp
)

ets2panda_add_gtest(ast_verifier_variable_has_enclosing_scope_test
    CPP_SOURCES ast_verifier_variable_has_enclosing_scope_test.cpp
)

ets2panda_add_gtest(ast_verifier_variable_has_scope_test
    CPP_SOURCES ast_verifier_variable_has_scope_test.cpp
)

ets2panda_add_gtest(ast_verifier_every_child_has_valid_parent_test
    CPP_SOURCES ast_verifier_every_child_has_valid_parent_test.cpp
)

ets2panda_add_gtest(ast_verifier_check_infinite_loop_test
    CPP_SOURCES ast_verifier_check_infinite_loop_test.cpp
)

ets2panda_add_gtest(ast_verifier_check_normal_loop_test
    CPP_SOURCES ast_verifier_check_normal_loop_test.cpp
)

ets2panda_add_gtest(ast_verifier_check_abstract_call_test
    CPP_SOURCES ast_verifier_check_abstract_call_test.cpp
)

ets2panda_add_gtest(ast_verifier_getter_setter_test
    CPP_SOURCES ast_verifier_getter_setter_test.cpp
)

ets2panda_add_gtest(ast_verifier_getter_setter_neg_test
    CPP_SOURCES ast_verifier_getter_setter_neg_test.cpp
)

panda_add_library(e2p_test_plugin SHARED e2p_test_plugin.c)
panda_target_include_directories(e2p_test_plugin
    PRIVATE "${ES2PANDA_PATH}"
    PRIVATE ${OUTPUT_DIR}
)
panda_target_link_libraries(e2p_test_plugin es2panda-public)


panda_add_library(e2p_test_plugin_dump_json SHARED e2p_test_plugin_dump_json.c)
panda_target_include_directories(e2p_test_plugin_dump_json
    PRIVATE "${ES2PANDA_PATH}"
    PRIVATE ${OUTPUT_DIR}
)
panda_target_link_libraries(e2p_test_plugin_dump_json es2panda-public)


panda_add_library(e2p_test_plugin_ets_src SHARED e2p_test_plugin_ets_src.c)
panda_target_include_directories(e2p_test_plugin_ets_src
    PRIVATE "${ES2PANDA_PATH}"
    PRIVATE ${OUTPUT_DIR}
)
panda_target_link_libraries(e2p_test_plugin_ets_src es2panda-public)


panda_add_library(e2p_test_plugin_is SHARED e2p_test_plugin_is.c)
panda_target_include_directories(e2p_test_plugin_is
    PRIVATE "${ES2PANDA_PATH}"
    PRIVATE ${OUTPUT_DIR}
)
panda_target_link_libraries(e2p_test_plugin_is es2panda-public)


add_custom_target(es2panda-plugin-test
  COMMENT "Test es2panda plugin functionality"

  COMMAND ${CMAKE_COMMAND} -E env
    LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda> --plugins=e2p_test_plugin
    --extension=sts "${CMAKE_CURRENT_SOURCE_DIR}/t.sts" > "${CMAKE_CURRENT_BINARY_DIR}/plugin_test.out"
  COMMAND ${CMAKE_COMMAND} -E compare_files
    "${CMAKE_CURRENT_BINARY_DIR}/plugin_test.out" "${CMAKE_CURRENT_SOURCE_DIR}/plugin_test-expected.txt"

  COMMAND ${CMAKE_COMMAND} -E env
    LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda> --plugins=e2p_test_plugin_dump_json
    "${CMAKE_CURRENT_SOURCE_DIR}/t.sts" > "${CMAKE_CURRENT_BINARY_DIR}/e2p_test_plugin_dump_json.out"
  COMMAND ${CMAKE_COMMAND} -E compare_files
    "${CMAKE_CURRENT_BINARY_DIR}/e2p_test_plugin_dump_json.out" "${CMAKE_CURRENT_SOURCE_DIR}/e2p_test_plugin_dump_json-expected.txt"

  COMMAND ${CMAKE_COMMAND} -E env
    LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda> --plugins=e2p_test_plugin_ets_src
    "${CMAKE_CURRENT_SOURCE_DIR}/t.sts" > "${CMAKE_CURRENT_BINARY_DIR}/e2p_test_plugin_ets_src.out"
  COMMAND ${CMAKE_COMMAND} -E compare_files
    "${CMAKE_CURRENT_BINARY_DIR}/e2p_test_plugin_ets_src.out" "${CMAKE_CURRENT_SOURCE_DIR}/e2p_test_plugin_ets_src-expected.txt"

  COMMAND ${CMAKE_COMMAND} -E env
    LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${PANDA_RUN_PREFIX} $<TARGET_FILE:es2panda> --plugins=e2p_test_plugin_is
    "${CMAKE_CURRENT_SOURCE_DIR}/t.sts" > "${CMAKE_CURRENT_BINARY_DIR}/e2p_test_plugin_is.out"
  COMMAND ${CMAKE_COMMAND} -E compare_files
    "${CMAKE_CURRENT_BINARY_DIR}/e2p_test_plugin_is.out" "${CMAKE_CURRENT_SOURCE_DIR}/e2p_test_plugin_is-expected.txt"
)


add_dependencies(es2panda-plugin-test es2panda e2p_test_plugin e2p_test_plugin_dump_json e2p_test_plugin_ets_src e2p_test_plugin_is)
add_dependencies(es2panda_tests es2panda-plugin-test)
