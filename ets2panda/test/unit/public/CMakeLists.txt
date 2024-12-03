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

ets2panda_add_gtest(ast_verifier_identifier_has_variable_test_1
    CPP_SOURCES ast_verifier_identifier_has_variable_test_1.cpp
)

ets2panda_add_gtest(ast_verifier_identifier_has_variable_test_2
    CPP_SOURCES ast_verifier_identifier_has_variable_test_2.cpp
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

ets2panda_add_gtest(ast_verifier_check_infinite_loop_test_1
    CPP_SOURCES ast_verifier_check_infinite_loop_test_1.cpp
)

ets2panda_add_gtest(ast_verifier_check_infinite_loop_test_2
    CPP_SOURCES ast_verifier_check_infinite_loop_test_2.cpp
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
ets2panda_add_gtest(ast_verifier_check_const_properties_test
    CPP_SOURCES ast_verifier_check_const_properties_test.cpp
)

ets2panda_add_gtest(ast_verifier_getter_setter_neg_test_1
    CPP_SOURCES ast_verifier_getter_setter_neg_test_1.cpp
)

ets2panda_add_gtest(ast_verifier_getter_setter_neg_test_2
    CPP_SOURCES ast_verifier_getter_setter_neg_test_2.cpp
)

ets2panda_add_gtest(ast_verifier_check_scope_declaration_test_1
    CPP_SOURCES ast_verifier_check_scope_declaration_test_1.cpp
)

ets2panda_add_gtest(ast_verifier_check_scope_declaration_test_2
    CPP_SOURCES ast_verifier_check_scope_declaration_test_2.cpp
)
