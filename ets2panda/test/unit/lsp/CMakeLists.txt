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
    get_file_references_test.cpp
    get_references_at_position_test.cpp
)

ets2panda_add_gtest(lsp_api_test CPP_SOURCES
    quick_info_test.cpp
    lsp_api_test.cpp
    classifier_test.cpp
    cancellation_token_test.cpp
    get_span_of_enclosing_comment_test.cpp
    user_preferences.cpp
)
