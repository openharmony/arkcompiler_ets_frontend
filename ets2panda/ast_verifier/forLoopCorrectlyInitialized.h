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

#ifndef ES2PANDA_COMPILER_CORE_AST_VERIFIER_FORLOOPCORRECTLYINITIALIZED_H
#define ES2PANDA_COMPILER_CORE_AST_VERIFIER_FORLOOPCORRECTLYINITIALIZED_H

#include "checkContext.h"

namespace ark::es2panda::compiler::ast_verifier {

class ForLoopCorrectlyInitialized : public RecursiveInvariant<VerifierInvariants::FOR_LOOP_CORRECTLY_INITIALIZED> {
    template <VerifierInvariants ID>
    friend class InvariantBase;
    [[nodiscard]] CheckResult operator()(const ir::AstNode *ast);
    [[nodiscard]] CheckResult HandleForInStatement(const ir::AstNode *ast);
    [[nodiscard]] CheckResult HandleForOfStatement(const ir::AstNode *ast);
    [[nodiscard]] CheckResult HandleForUpdateStatement(const ir::AstNode *ast);
};

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_AST_VERIFIER_FORLOOPCORRECTLYINITIALIZED_H
