/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_CHECKER_SEMANTICANALYZER_H
#define ES2PANDA_CHECKER_SEMANTICANALYZER_H

#include "compiler/core/dynamicContext.h"

namespace panda::es2panda::checker {
class Checker;

class SemanticAnalyzer {
public:
    explicit SemanticAnalyzer(Checker *checker)
    {
        checker_ = checker;
    }
    virtual ~SemanticAnalyzer() = default;
    NO_COPY_SEMANTIC(SemanticAnalyzer);
    NO_MOVE_SEMANTIC(SemanticAnalyzer);

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AST_NODE_CHECK_METHOD(_, nodeType) virtual checker::Type *Check(ir::nodeType *node) const = 0;
    AST_NODE_MAPPING(DECLARE_AST_NODE_CHECK_METHOD)
#undef DECLARE_AST_NODE_CHECK_METHOD

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AST_NODE_CHECK_METHOD(_, __, nodeType, ___) virtual checker::Type *Check(ir::nodeType *node) const = 0;
    AST_NODE_REINTERPRET_MAPPING(DECLARE_AST_NODE_CHECK_METHOD)
#undef DECLARE_AST_NODE_CHECK_METHOD

protected:
    Checker *GetChecker() const
    {
        return checker_;
    }

private:
    Checker *checker_;
};
}  // namespace panda::es2panda::checker

#endif  // ES2PANDA_CHECKER_SEMANTICANALYZER_H
