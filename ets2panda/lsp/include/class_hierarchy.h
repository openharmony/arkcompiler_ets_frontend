/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ES2PANDA_LSP_INCLUDE_CLASSHIERARCHY_H
#define ES2PANDA_LSP_INCLUDE_CLASSHIERARCHY_H

#include <tuple>
#include <vector>
#include "ir/astNode.h"
#include "line_column_offset.h"
#include "public/es2panda_lib.h"

namespace ark::es2panda::lsp {

using ClassHierarchyInfoType = std::tuple<size_t, std::string, std::string>;

enum class HierarchyType { OTHERS, INTERFACE, CLASS };

// NOLINTBEGIN(misc-non-private-member-variables-in-classes)
struct TypeHierarchies {
    TypeHierarchies() = default;
    TypeHierarchies(std::string f, std::string n, HierarchyType t, size_t p)
        : fileName(std::move(f)), name(std::move(n)), type(t), pos(p)
    {
    }
    bool operator==(const TypeHierarchies &other) const
    {
        return fileName == other.fileName && name == other.name && type == other.type && pos == other.pos;
    }
    bool operator!=(const TypeHierarchies &other) const
    {
        return !(*this == other);
    }
    bool operator<(const TypeHierarchies &other) const
    {
        return std::tie(fileName, name, type, pos) < std::tie(other.fileName, other.name, other.type, other.pos);
    }
    std::string fileName;
    std::string name;
    HierarchyType type = HierarchyType::OTHERS;
    size_t pos = 0;
    std::vector<TypeHierarchies> subOrSuper;
};

struct TypeHierarchiesInfo {
    TypeHierarchiesInfo() = default;
    TypeHierarchiesInfo(std::string f, std::string n, HierarchyType t, size_t p)
        : fileName(std::move(f)), name(std::move(n)), type(t), pos(p)
    {
    }
    std::string fileName;
    std::string name;
    HierarchyType type = HierarchyType::OTHERS;
    size_t pos = 0;
    TypeHierarchies superHierarchies;
    TypeHierarchies subHierarchies;
};
// NOLINTEND(misc-non-private-member-variables-in-classes)

ir::AstNode *GetTargetDeclarationNodeByPosition(es2panda_Context *context, size_t pos);
void GetSuperTypeHierarchies(const ir::AstNode *node, TypeHierarchies &typeHierarchies,
                             std::set<TypeHierarchies> &superLists);
TypeHierarchiesInfo GetTypeHierarchiesImpl(es2panda_Context *context, const ClassHierarchyInfoType &declInfo,
                                           const ir::AstNode *declaration = nullptr);
}  // namespace ark::es2panda::lsp
#endif