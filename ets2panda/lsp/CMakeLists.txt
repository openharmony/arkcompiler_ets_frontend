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

# build liblsp.node
if(PANDA_TS_BINDINGS)
  set(NODE_VERSION "v18.13.0")
  set(DISTRO "linux-x64")

  execute_process(COMMAND ${PANDA_ROOT}/scripts/install-third-party --node
    WORKING_DIRECTORY ${PANDA_ROOT}
    RESULT_VARIABLE NODEJS_DOWNLOAD_OK)
  if(NOT NODEJS_DOWNLOAD_OK EQUAL 0)
    message(FATAL_ERROR "Unable to install required nodejs dependencies")
  endif()

  set(NODE_THIRD_PARTY_SOURCES_DIR ${PANDA_THIRD_PARTY_SOURCES_DIR}/nodejs)
  set(NAPI_HEADERS_PATH ${NODE_THIRD_PARTY_SOURCES_DIR}/node-${NODE_VERSION}-${DISTRO}/include/node)
  set(NODE_ADDON_API_HEADERS_PATH ${PANDA_THIRD_PARTY_SOURCES_DIR}/node-addon-api)

  set(LSP_NODE_LIB "lsp")

  set(LSP_NODE_SOURCES
    src/lsp_bindings.cpp
  )

  set(ES2PANDA_LIBS
    es2panda-lib
    es2panda-public
    es2panda_lsp
  )

  if(PANDA_TARGET_WINDOWS)
    set(NODE_API_LIB libnode_api.a)
    set(NODE_WIN_API_LIB_PATH ${NODE_THIRD_PARTY_SOURCES_DIR}/node-${NODE_VERSION}-${DISTRO}/lib/${NODE_API_LIB})
    list(APPEND ES2PANDA_LIBS ${NODE_WIN_API_LIB_PATH})
    list(APPEND LSP_NODE_SOURCES ../bindings/native/src/win-dynamic-node.cpp)
  endif()

  panda_add_library(${LSP_NODE_LIB} SHARED ${LSP_NODE_SOURCES})

  add_definitions(-DNODE_ADDON_API_CPP_EXCEPTIONS)

  set_target_properties(${LSP_NODE_LIB} PROPERTIES SUFFIX ".node")

  panda_target_include_directories(${LSP_NODE_LIB}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    SYSTEM PRIVATE ${NAPI_HEADERS_PATH}
    SYSTEM PRIVATE ${NODE_ADDON_API_HEADERS_PATH}
    PRIVATE ${ES2PANDA_ROOT}
    PRIVATE ${OUTPUT_DIR}
  )

  panda_target_compile_options(${LSP_NODE_LIB}
    PRIVATE -fexceptions -Werror=shadow
  )

  panda_target_link_libraries(${LSP_NODE_LIB} PRIVATE
    ${ES2PANDA_LIBS}
  )
endif()
