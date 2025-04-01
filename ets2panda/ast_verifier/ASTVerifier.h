/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "ast_verifier/checkStructDeclaration.h"
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

#ifdef ASTV_ENABLE_LOGGING
// CC-OFFNXT(G.PRE.02) macro to enable conditionally
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LOG_ASTV(lvl, msg) LOG(lvl, ES2PANDA) << "[ASTV] " << msg
#else
// CC-OFFNXT(G.PRE.02) macro to enable conditionally
#define LOG_ASTV(lvl, msg)
#endif  // ASTV_ENABLE_LOGGING

namespace ark::es2panda::compiler::ast_verifier {

template <typename... Invs>
class InvariantsRegistryImpl {
public:
    using Invariants = std::tuple<Invs...>;
    template <VerifierInvariants ID>
    using InvariantClass = std::tuple_element_t<ID, Invariants>;
    template <typename T>
    using InvArray = std::array<T, VerifierInvariants::COUNT>;

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
                      "index of the invariant in `InvariantsRegistryImpl` parameter-list");
        return true;
    }

protected:
    Invariants invariants_ {};

    static_assert(sizeof...(Invs) == VerifierInvariants::COUNT,
                  "Parameter-list is inconsistent with invaraints' declararation in 'options.yaml'");
    static_assert(CheckRegistry(std::make_index_sequence<sizeof...(Invs)> {}));
};

// NOTE(dkofanov) Fix and enable ImportExportAccessValid:
using InvariantsRegistry =
    InvariantsRegistryImpl<NodeHasParent, NodeHasSourceRange, EveryChildHasValidParent, EveryChildInParentRange,
                           CheckStructDeclaration, VariableHasScope, NodeHasType, NoPrimitiveTypes,
                           IdentifierHasVariable, ReferenceTypeAnnotationIsNull, ArithmeticOperationValid,
                           SequenceExpressionHasLastType, CheckInfiniteLoop, ForLoopCorrectlyInitialized,
                           VariableHasEnclosingScope, ModifierAccessValid, VariableNameIdentifierNameSame,
                           CheckAbstractMethod, GetterSetterValidation, CheckScopeDeclaration, CheckConstProperties>;

/*
 * ASTVerifier checks whether various conditions are invariant (across AST transformations).
 */
class ASTVerifier : public InvariantsRegistry {
public:
    NO_COPY_SEMANTIC(ASTVerifier);
    NO_MOVE_SEMANTIC(ASTVerifier);

    ASTVerifier(const public_lib::Context &context, const parser::Program &program)
        : program_ {program}, options_ {*context.config->options}
    {
        for (size_t i = VerifierInvariants::BASE_FIRST; i <= VerifierInvariants::BASE_LAST; i++) {
            allowed_[i] = true;
        }
        for (size_t i = 0; i < VerifierInvariants::COUNT; i++) {
            enabled_[i] = TreatAsWarning(VerifierInvariants {i}) || TreatAsError(VerifierInvariants {i});
        }
        if (options_.IsAstVerifierBeforePhases()) {
            Verify("before");
        }
    }

    ~ASTVerifier()
    {
        if (!suppressed_) {
            if (options_.IsAstVerifierAfterPhases()) {
                Verify("after");
            }
            if (HasErrors() || HasWarnings()) {
                DumpMessages();
            }
        }
    }

    void Verify(std::string_view phaseName);

    void IntroduceNewInvariants(std::string_view occurredPhaseName)
    {
        if (occurredPhaseName == "plugins-after-parse") {
            for (size_t i = VerifierInvariants::AFTER_PLUGINS_AFTER_PARSE_FIRST;
                 i <= VerifierInvariants::AFTER_PLUGINS_AFTER_PARSE_LAST; i++) {
                allowed_[i] = true;
            }
        }
        if (occurredPhaseName == "ScopesInitPhase") {
            for (size_t i = VerifierInvariants::AFTER_SCOPES_INIT_PHASE_FIRST;
                 i <= VerifierInvariants::AFTER_SCOPES_INIT_PHASE_LAST; i++) {
                allowed_[i] = true;
            }
        }
        if (occurredPhaseName == "CheckerPhase") {
            for (size_t i = VerifierInvariants::AFTER_CHECKER_PHASE_FIRST;
                 i <= VerifierInvariants::AFTER_CHECKER_PHASE_LAST; i++) {
                allowed_[i] = true;
            }
            // NOTE(dkofanov): This should be called after "NumberLowering" phase:
            std::get<NoPrimitiveTypes>(invariants_).SetNumberLoweringOccured();
        }
        if (occurredPhaseName == "UnionLowering") {
            std::get<IdentifierHasVariable>(invariants_).SetUnionLoweringOccurred();
        }
    }

    void Suppress()
    {
        suppressed_ = true;
    }

    void DumpMessages() const;

    bool TreatAsWarning(VerifierInvariants id) const
    {
        return options_.GetAstVerifierWarnings()[id];
    }
    bool TreatAsError(VerifierInvariants id) const
    {
        return options_.GetAstVerifierErrors()[id];
    }
    bool HasErrors() const
    {
        return hasErrors_;
    }
    bool HasWarnings() const
    {
        return hasWarnings_;
    }

private:
    template <typename T, std::enable_if_t<std::is_base_of_v<InvariantBase<T::ID>, T>, void *> = nullptr>
    bool NeedCheckInvariant(const T & /*unused*/)
    {
        return enabled_[T::ID] && allowed_[T::ID];
    }

public:
    using SourcePath = std::string_view;
    using PhaseName = std::string_view;
    using InvariantsMessages = std::map<VerifierInvariants, Messages>;
    using WarningsErrors = std::map<std::string_view, InvariantsMessages>;
    using SourceMessages = std::map<SourcePath, WarningsErrors>;
    using GroupedMessages = std::vector<std::pair<PhaseName, SourceMessages>>;

private:
    const parser::Program &program_;
    const util::Options &options_;
    InvArray<bool> enabled_ {};
    InvArray<bool> allowed_ {};

    bool hasErrors_ {false};
    bool hasWarnings_ {false};
    bool suppressed_ {false};
    GroupedMessages report_;

    struct SinglePassVerifier;
};

template <VerifierInvariants ID>
CheckResult InvariantBase<ID>::VerifyNode(const ir::AstNode *ast)
{
    auto [res, action] = (*static_cast<ASTVerifier::InvariantClass<ID> *>(this))(ast);
    if (action == CheckAction::SKIP_SUBTREE) {
        LOG_ASTV(DEBUG, util::gen::ast_verifier::ToString(ID) << ": SKIP_SUBTREE");
    }
    return {res, action};
}

template <VerifierInvariants ID>
void RecursiveInvariant<ID>::VerifyAst(const ir::AstNode *ast)
{
    std::function<void(const ir::AstNode *)> aux {};
    aux = [this, &aux](const ir::AstNode *child) -> void {
        const auto [_, action] = this->VerifyNode(child);
        if (action == CheckAction::SKIP_SUBTREE) {
            return;
        }
        child->Iterate(aux);
    };
    aux(ast);
}

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
