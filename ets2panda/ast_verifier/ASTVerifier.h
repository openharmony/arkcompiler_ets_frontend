/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
#define ES2PANDA_COMPILER_CORE_ASTVERIFIER_H

#include <algorithm>
#include <iterator>
#include <regex>
#include <string>
#include <unordered_set>

#include "ast_verifier/checkContext.h"
#include "ast_verifier/sequenceExpressionHasLastType.h"
#include "ast_verifier/checkAbstractMethod.h"
#include "ast_verifier/checkInfiniteLoop.h"
#include "ast_verifier/everyChildHasValidParent.h"
#include "ast_verifier/everyChildInParentRange.h"
#include "ast_verifier/getterSetterValidation.h"
#include "ast_verifier/identifierHasVariable.h"
#include "ast_verifier/nodeHasParent.h"
#include "ast_verifier/nodeHasSourceRange.h"
#include "ast_verifier/nodeHasType.h"
#include "ast_verifier/referenceTypeAnnotationIsNull.h"
#include "ast_verifier/variableHasScope.h"
#include "ast_verifier/variableHasEnclosingScope.h"
#include "ast_verifier/forLoopCorrectlyInitialized.h"
#include "ast_verifier/modifierAccessValid.h"
#include "ast_verifier/importExportAccessValid.h"
#include "ast_verifier/arithmeticOperationValid.h"
#include "ast_verifier/variableNameIdentifierNameSame.h"
#include "ast_verifier/checkScopeDeclaration.h"
#include "ast_verifier/checkConstProperties.h"

#include "ir/astNode.h"
#include "ir/statements/blockStatement.h"
#include "lexer/token/sourceLocation.h"
#include "parser/program/program.h"
#include "util/ustring.h"
#include "util/options.h"
#include "utils/arena_containers.h"
#include "varbinder/variable.h"
#include "public/public.h"

namespace ark::es2panda::compiler::ast_verifier {

template <typename... Invs>
class InvariantsRegistry {
public:
    template <VerifierInvariants ID>
    using InvariantClass = std::remove_reference_t<decltype(std::get<ID>(std::declval<std::tuple<Invs...>>()))>;

private:
    template <typename T, T... INTS>
    static constexpr bool CheckRegistry(std::integer_sequence<T, INTS...> /*unused*/)
    {
        return ((CheckRegistry<VerifierInvariants(INTS), Invs::ID>()) && ...);
    }

    template <VerifierInvariants ORDER_IN_PARAMETER_LIST, VerifierInvariants DEFINED_ENUM>
    static constexpr bool CheckRegistry()
    {
        static_assert(ORDER_IN_PARAMETER_LIST == DEFINED_ENUM,
                      "Invariant's `ID` must be equal to"
                      "index of the invariant in `InvariantsRegistry` parameter-list");
        return true;
    }

protected:
    std::tuple<Invs...> invariants_ {};

    static_assert(sizeof...(Invs) == VerifierInvariants::COUNT,
                  "Parameter-list is inconsistent with invaraints' declararation in 'options.yaml'");
    static_assert(CheckRegistry(std::make_index_sequence<sizeof...(Invs)> {}));
};

/*
 * ASTVerifier used for checking various invariants that should hold during AST transformation in lowerings
 * For all available checks lookup the constructor
 *
 * NOTE(dkofanov) Fix and enable ImportExportAccessValid
 */
class ASTVerifier
    : public InvariantsRegistry<NodeHasParent, NodeHasSourceRange, EveryChildHasValidParent, EveryChildInParentRange,
                                VariableHasScope, NodeHasType, IdentifierHasVariable, ReferenceTypeAnnotationIsNull,
                                ArithmeticOperationValid, SequenceExpressionHasLastType, CheckInfiniteLoop,
                                ForLoopCorrectlyInitialized, VariableHasEnclosingScope, ModifierAccessValid,
                                VariableNameIdentifierNameSame, CheckAbstractMethod, GetterSetterValidation,
                                CheckScopeDeclaration, CheckConstProperties> {
public:
    using AstPath = std::string;
    using PhaseName = std::string;
    using Source = std::tuple<AstPath, PhaseName>;
    using GroupedMessages = std::map<Source, ast_verifier::Messages>;

    ASTVerifier() = default;
    ASTVerifier(const public_lib::Context &context, const parser::Program &program)
        : program_ {&program},
          checkFullProgram_ {context.config->options->IsVerifierInvariantsFullProgram()},
          treatAsWarnings_ {&context.config->options->GetVerifierInvariantsAsWarnings()},
          treatAsErrors_ {&context.config->options->GetVerifierInvariantsAsErrors()}
    {
        for (size_t i = 0; i < VerifierInvariants::COUNT; i++) {
            enabled_[i] = IsAsWarning(VerifierInvariants(i)) || IsAsError(VerifierInvariants(i));
        }
    }

    void Verify(std::string_view phaseName);

    template <typename Invariant>
    Messages Verify(const ir::AstNode *ast)
    {
        CheckContext ctx {};
        std::get<Invariant>(invariants_).VerifyAst(&ctx, ast);
        return ctx.GetMessages();
    }

    template <typename Invariant>
    Messages VerifyNode(const ir::AstNode *ast)
    {
        CheckContext ctx {};
        std::get<Invariant>(invariants_).VerifyNode(&ctx, ast);
        return ctx.GetMessages();
    }

    void IntroduceNewInvariants(std::string_view phaseName)
    {
        if (phaseName == "ScopesInitPhase") {
            for (size_t i = VerifierInvariants::AFTER_SCOPES_INIT_PHASE_FIRST;
                 i <= VerifierInvariants::AFTER_SCOPES_INIT_PHASE_LAST; i++) {
                allowed_[i] = true;
            }
        }
        if (phaseName == "CheckerPhase") {
            for (size_t i = VerifierInvariants::AFTER_CHECHER_PHASE_FIRST;
                 i <= VerifierInvariants::AFTER_CHECHER_PHASE_LAST; i++) {
                allowed_[i] = true;
            }
        }
    }

    class Result {
    public:
        explicit Result(JsonArrayBuilder &&warnings, JsonArrayBuilder &&errors)
            : warnings_ {std::move(warnings)}, errors_ {std::move(errors)}
        {
        }

        JsonArrayBuilder &&Warnings()
        {
            return std::move(warnings_);
        }

        JsonArrayBuilder &&Errors()
        {
            return std::move(errors_);
        }

    private:
        JsonArrayBuilder warnings_;
        JsonArrayBuilder errors_;
    };

    Result DumpMessages();

private:
    bool IsAsWarning(VerifierInvariants id)
    {
        return (*treatAsWarnings_)[id];
    }
    bool IsAsError(VerifierInvariants id)
    {
        return (*treatAsErrors_)[id];
    }
    template <typename T, std::enable_if_t<std::is_base_of_v<InvariantBase<T::ID>, T>, void *> = nullptr>
    bool NeedCheckVariant(const T & /*unused*/)
    {
        return enabled_[T::ID] && allowed_[T::ID];
    }

private:
    const parser::Program *program_ {};
    bool checkFullProgram_ {};
    const std::array<bool, VerifierInvariants::COUNT> *treatAsWarnings_ {};
    const std::array<bool, VerifierInvariants::COUNT> *treatAsErrors_ {};
    std::array<bool, VerifierInvariants::COUNT> enabled_ {};
    std::array<bool, VerifierInvariants::COUNT> allowed_ {};
    GroupedMessages report_;
};

template <VerifierInvariants ID>
CheckResult InvariantBase<ID>::VerifyNode(CheckContext *ctx, const ir::AstNode *ast)
{
    ctx->SetInvariantId(ID);
    return (*static_cast<ASTVerifier::InvariantClass<ID> *>(this))(*ctx, ast);
}

template <VerifierInvariants ID>
void RecursiveInvariant<ID>::VerifyAst(CheckContext *ctx, const ir::AstNode *ast)
{
    std::function<void(const ir::AstNode *)> aux;
    auto finalDecision = CheckDecision::CORRECT;
    aux = [this, ctx, &aux, &finalDecision](const ir::AstNode *child) -> void {
        const auto [decision, action] = this->VerifyNode(ctx, child);
        if (decision == CheckDecision::INCORRECT) {
            finalDecision = CheckDecision::INCORRECT;
        }
        if (action == CheckAction::SKIP_SUBTREE) {
            return;
        }
        child->Iterate(aux);
    };
    aux(ast);
}

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
