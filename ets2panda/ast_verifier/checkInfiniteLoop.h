/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_AST_VERIFIER_CHECKINFINITELOOP_H
#define ES2PANDA_COMPILER_CORE_AST_VERIFIER_CHECKINFINITELOOP_H

#include "checkContext.h"

namespace ark::es2panda::compiler::ast_verifier {

class CheckInfiniteLoop : public RecursiveInvariant<VerifierInvariants::CHECK_INFINITE_LOOP> {
    template <VerifierInvariants ID>
    friend class InvariantBase;
    [[nodiscard]] CheckResult operator()(const ir::AstNode *ast);
    bool ConditionIsAlwaysTrue(const ir::Expression *const test) const;
    bool HasBreakOrReturnStatement(const ir::Statement *const body) const;
    [[nodiscard]] CheckResult HandleWhileStatement(const ir::WhileStatement *const stmt);
    [[nodiscard]] CheckResult HandleDoWhileStatement(const ir::DoWhileStatement *const stmt);
    [[nodiscard]] CheckResult HandleForUpdateStatement(const ir::ForUpdateStatement *const stmt);
};

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_AST_VERIFIER_CHECKINFINITELOOP_H
