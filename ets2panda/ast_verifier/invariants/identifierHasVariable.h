/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_AST_VERIFIER_INVARIANTS_IDENTIFIERHASVARIABLE_H
#define ES2PANDA_COMPILER_CORE_AST_VERIFIER_INVARIANTS_IDENTIFIERHASVARIABLE_H

#include "../invariantBase.h"

#include "ir/expressions/identifier.h"

namespace ark::es2panda::compiler::ast_verifier {

class IdentifierHasVariable : public InvariantBase<VerifierInvariants::IDENTIFIER_HAS_VARIABLE> {
public:
    using Base::Base;
    class ExceptionsMatcher;
    [[nodiscard]] CheckResult operator()(const ir::AstNode *ast);

private:
    auto UnionLoweringOccurred() const
    {
        return unionLoweringOccurred_;
    }

public:
    void SetUnionLoweringOccurred()
    {
        unionLoweringOccurred_ = true;
    }

private:
    bool unionLoweringOccurred_ {false};
};

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_AST_VERIFIER_INVARIANTS_IDENTIFIERHASVARIABLE_H
