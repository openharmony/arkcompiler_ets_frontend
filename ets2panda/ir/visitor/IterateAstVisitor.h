/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_ITERATE_AST_VISITOR_H
#define ES2PANDA_COMPILER_CORE_ITERATE_AST_VISITOR_H

#include "AstVisitor.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/expressions/blockExpression.h"
#include "ir/ets/etsUnionType.h"
#include "ir/ets/etsTuple.h"

namespace ark::es2panda::ir::visitor {

/**
 * Children should declare VisitNode methods (might be virtual might be not)
 * for all classes or provide default behaviour using
 * template <T> VisitNode(T *t) {}
 */
class IterateAstVisitor : public ASTAbstractVisitor {
public:
    IterateAstVisitor() = default;
    virtual ~IterateAstVisitor() = 0;
    NO_COPY_SEMANTIC(IterateAstVisitor);
    NO_MOVE_SEMANTIC(IterateAstVisitor);

    void Iterate(ir::AstNode *node)
    {
        if (node != nullptr) {
            node->Iterate([this](ir::AstNode *child) { child->Accept(this); });
        }
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CLASSES(nodeType, className)        \
    void Visit##className(className *node) override \
    {                                               \
        Iterate(static_cast<ir::AstNode *>(node));  \
    }

    AST_NODE_MAPPING(DECLARE_CLASSES)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AST_NODE_CHECK_METHOD(nodeType1, nodeType2, baseClass, reinterpretClass) \
    DECLARE_CLASSES(nodeType1, baseClass);

    AST_NODE_REINTERPRET_MAPPING(DECLARE_AST_NODE_CHECK_METHOD)
#undef DECLARE_AST_NODE_CHECK_METHOD

#undef DECLARE_CLASSES
};
inline IterateAstVisitor::~IterateAstVisitor() = default;

}  // namespace ark::es2panda::ir::visitor

#endif
