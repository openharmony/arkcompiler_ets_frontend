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

#ifndef ES2PANDA_COMPILER_CORE_AST_VERIFIER_NODEHASTYPE_H
#define ES2PANDA_COMPILER_CORE_AST_VERIFIER_NODEHASTYPE_H

#include "checkContext.h"
#include "checker/types/type.h"

namespace ark::es2panda::compiler::ast_verifier {

class NodeHasType : public RecursiveInvariant<VerifierInvariants::NODE_HAS_TYPE> {
    template <VerifierInvariants ID>
    friend class InvariantBase;
    [[nodiscard]] CheckResult operator()(const ir::AstNode *ast);
    CheckResult CheckCompound(const ir::AstNode *ast);
};

// NOTE(dkofanov): explicitly mark as dependent on NodeHasType:
class NoPrimitiveTypes : public RecursiveInvariant<VerifierInvariants::NO_PRIMITIVE_TYPES> {
public:
    void SetNumberLoweringOccured(bool v = true)
    {
        numberLoweringOccurred_ = v;
    }

    [[nodiscard]] CheckResult operator()(const ir::AstNode *ast)
    {
        if (!ast->IsTyped()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
        auto type = ast->AsTyped()->TsType();
        if (type == nullptr) {
            // Checked during NodeHasType.
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }

        if (!numberLoweringOccurred_ && type->IsETSPrimitiveType()) {
            AddCheckMessage("PRIMITIVE_BEFORE_LOWERING", *ast);
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

private:
    bool numberLoweringOccurred_ {false};
};
}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_AST_VERIFIER_NODEHASTYPE_H
