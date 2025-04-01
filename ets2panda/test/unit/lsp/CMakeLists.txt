# Copyright (c) 2025 Huawei Device Co., Ltd.
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

ets2panda_add_gtest(lsp_api_test_1 CPP_SOURCES
    get_definition_at_position_test.cpp
    get_file_references_test.cpp
    get_references_at_position_test.cpp
    document_highlights.cpp
)

ets2panda_add_gtest(lsp_api_test CPP_SOURCES
    lsp_api_test.cpp
    cancellation_token_test.cpp
    get_span_of_enclosing_comment_test.cpp
    user_preferences.cpp
    keyword_completion_data_test.cpp
    lsp_rename_test.cpp
)

ets2panda_add_gtest(lsp_quick_info_api_test CPP_SOURCES
    quick_info_test.cpp
)

ets2panda_add_gtest(lsp_api_classifier_test CPP_SOURCES
    classifier_test.cpp
)

ets2panda_add_gtest(lsp_api_diagnostics_test CPP_SOURCES
    get_compiler_options_diagnostics_test.cpp
    get_diagnostics.cpp
)

ets2panda_add_gtest(lsp_api_get_adjusted_location_test CPP_SOURCES
    get_adjusted_location_test.cpp
)

ets2panda_add_gtest(lsp_api_test_find_references CPP_SOURCES
    find_references_test.cpp
)

ets2panda_add_gtest(lsp_api_slc_tests CPP_SOURCES
    string_completions_test.cpp
)

ets2panda_add_gtest(lsp_api_test_suggestion_diagnostics CPP_SOURCES
    suggestion_diagnostics_test.cpp
)

ets2panda_add_gtest(lsp_api_test_brace_matching CPP_SOURCES
    brace_matching_test.cpp
)

ets2panda_add_gtest(lsp_api_completions_test CPP_SOURCES
    get_completions.cpp
)

ets2panda_add_gtest(lsp_api_gilap_test CPP_SOURCES
    get_implementation_location.cpp
)

ets2panda_add_gtest(lsp_api_lco_test CPP_SOURCES
    line_column_offset_test.cpp
)

ets2panda_add_gtest(lsp_api_test_auto_completion CPP_SOURCES
    get_auto_completion_test.cpp
)

ets2panda_add_gtest(lsp_api_test_inlay_hints CPP_SOURCES
    inlay_hints_test.cpp
)

ets2panda_add_gtest(lsp_api_test_find_rename_locations CPP_SOURCES
    find_rename_locations_test.cpp
)
