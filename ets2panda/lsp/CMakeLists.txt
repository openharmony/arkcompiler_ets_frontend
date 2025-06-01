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

set(ES2PANDA_LSP_SRC
  ./src/api.cpp
  ./src/classifier.cpp
  ./src/internal_api.cpp
  ./src/cancellation_token.cpp
  ./src/completions.cpp
  ./src/quick_info.cpp
  ./src/references.cpp
  ./src/get_adjusted_location.cpp
  ./src/find_rename_locations.cpp
  ./src/find_references.cpp
  ./src/string_completions.cpp
  ./src/rename.cpp
  ./src/suggestion_diagnostics.cpp
  ./src/brace_matching.cpp
  ./src/services/services.cpp
  ./src/services/utilities.cpp
  ./src/line_column_offset.cpp
  ./src/inlay_hints.cpp
)

panda_add_library(${LSP_LIB} SHARED ${ES2PANDA_LSP_SRC})

panda_target_include_directories(${LSP_LIB}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${ES2PANDA_ROOT}
  PRIVATE ${OUTPUT_DIR}
)

panda_target_compile_options(${LSP_LIB}
  PRIVATE -fexceptions -Werror=shadow
)

panda_target_link_libraries(${LSP_LIB}
  PUBLIC arkbase es2panda-lib es2panda-public
  PRIVATE arkbytecodeopt
)

panda_add_sanitizers(TARGET ${LSP_LIB} SANITIZERS
  ${PANDA_SANITIZERS_LIST})
