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

if(NOT PANDA_WITH_ETS)
    return()
endif()

ets2panda_add_gtest(plugin_conversion_rule_test CPP_SOURCES 
    plugin_conversion_rule_part_i.cpp
    plugin_conversion_rule_part_ii.cpp
    plugin_conversion_rule_part_iii.cpp
    plugin_conversion_rule_part_iv.cpp
)