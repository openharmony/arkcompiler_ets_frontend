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

#include "ir/astNode.h"
#include "ir/statements/blockStatement.h"
#include "lexer/token/sourceLocation.h"
#include "parser/program/program.h"
#include "util/ustring.h"
#include "utils/arena_containers.h"
#include "utils/json_builder.h"
#include "varbinder/variable.h"

namespace ark::es2panda::compiler::ast_verifier {

enum class CheckSeverity { ERROR, WARNING, UNKNOWN };
inline std::string CheckSeverityString(CheckSeverity value)
{
    switch (value) {
        case CheckSeverity::ERROR:
            return "error";
        case CheckSeverity::WARNING:
            return "warning";
        default:
            UNREACHABLE();
    }
}

class CheckMessage {
public:
    explicit CheckMessage(util::StringView name, util::StringView cause, util::StringView message, size_t line)
        : invariantName_ {name}, cause_ {cause}, message_ {message}, line_ {line}
    {
    }

    std::string Invariant() const
    {
        return invariantName_;
    }

    std::function<void(JsonObjectBuilder &)> DumpJSON(CheckSeverity severity, const std::string &sourceName,
                                                      const std::string &phaseName) const
    {
        return [sourceName, phaseName, severity, this](JsonObjectBuilder &body) {
            body.AddProperty("severity", CheckSeverityString(severity));
            body.AddProperty("invariant", invariantName_);
            body.AddProperty("cause", cause_);
            body.AddProperty("ast", message_);
            body.AddProperty("line", line_ + 1);
            body.AddProperty("source", sourceName);
            body.AddProperty("phase", phaseName);
        };
    }

private:
    std::string invariantName_;
    std::string cause_;
    std::string message_;
    size_t line_;
};
using Messages = std::vector<CheckMessage>;

enum class CheckDecision { CORRECT, INCORRECT };
enum class CheckAction { CONTINUE, SKIP_SUBTREE };
using CheckResult = std::tuple<CheckDecision, CheckAction>;
class CheckContext;
using InvariantCheck = std::function<CheckResult(CheckContext &ctx, const ir::AstNode *)>;
using Invariants = std::unordered_map<std::string, InvariantCheck>;

using InvariantNameSet = std::unordered_set<std::string>;

class VerificationContext final {
public:
    void IntroduceNewInvariants(util::StringView phaseName)
    {
        auto invariantSet = [phaseName]() -> std::optional<InvariantNameSet> {
            if (phaseName == "ScopesInitPhase") {
                return {{
                    "NodeHasParentForAll",
                    "EveryChildHasValidParentForAll",
                    "VariableHasScopeForAll",
                }};
            }
            if (phaseName == "CheckerPhase") {
                return {{
                    "NodeHasTypeForAll",
                    "IdentifierHasVariableForAll",
                    "ArithmeticOperationValidForAll",
                    "SequenceExpressionHasLastTypeForAll",
                    "ForLoopCorrectlyInitializedForAll",
                    "VariableHasEnclosingScopeForAll",
                    "ModifierAccessValidForAll",
                    "ImportExportAccessValid",
                }};
            }
            const std::set<std::string> withoutAdditionalChecks = {"OptionalLowering",
                                                                   "PromiseVoidInferencePhase",
                                                                   "StructLowering",
                                                                   "DefaultParameterLowering",
                                                                   "BigIntLowering",
                                                                   "GenerateTsDeclarationsPhase",
                                                                   "InterfacePropertyDeclarationsPhase",
                                                                   "LambdaConstructionPhase",
                                                                   "ObjectIndexLowering",
                                                                   "ObjectIteratorLowering",
                                                                   "OpAssignmentLowering",
                                                                   "PromiseVoidInferencePhase",
                                                                   "TupleLowering",
                                                                   "UnionLowering",
                                                                   "ExpandBracketsPhase"};
            if (withoutAdditionalChecks.count(phaseName.Mutf8()) > 0) {
                return {{}};
            };
            if (phaseName.Utf8().find("plugins-after") != std::string_view::npos) {
                return {{}};
            }
            return std::nullopt;
        }();

        ASSERT_PRINT(invariantSet.has_value(),
                     std::string {"Invariant set does not contain value for "} + phaseName.Mutf8());
        for (const auto &check : *invariantSet) {
            accumulatedChecks_.insert(check);
        }
    }

    const InvariantNameSet &AccumulatedChecks() const
    {
        return accumulatedChecks_;
    }

private:
    InvariantNameSet accumulatedChecks_ {};
};

/*
 * ASTVerifier used for checking various invariants that should hold during AST transformation in lowerings
 * For all available checks lookup the constructor
 */
class ASTVerifier final {
public:
    NO_COPY_SEMANTIC(ASTVerifier);
    NO_MOVE_SEMANTIC(ASTVerifier);

    explicit ASTVerifier(ArenaAllocator *allocator);
    ~ASTVerifier() = default;

    /**
     * @brief Run all existing invariants on some ast node (and consequently it's children)
     * @param ast AstNode which will be analyzed
     * @return Messages report of analysis
     */
    Messages VerifyFull(const ir::AstNode *ast);

    /**
     * @brief Run some particular invariants on some ast node
     * @note invariants must be supplied as strings to invariant_set, additionally invariant
     * name can be suffixed by `ForAll` string to include recursive analysis of provided node
     * I.e. 'HasParent' invariant can be named 'HasParentRecursive' to traverse all child nodes as well
     * @param ast AstNode which will be analyzed
     * @param invariantSet Set of invariants to check
     * @return Messages report of analysis
     */
    Messages Verify(const ir::AstNode *ast, const InvariantNameSet &invariantSet);

private:
    static constexpr const char *RECURSIVE_SUFFIX = "ForAll";

    static InvariantCheck RecursiveInvariant(const InvariantCheck &func)
    {
        return [func](CheckContext &ctx, const ir::AstNode *ast) -> CheckResult {
            std::function<void(const ir::AstNode *)> aux;
            auto finalDecision = CheckDecision::CORRECT;
            aux = [&ctx, func, &aux, &finalDecision](const ir::AstNode *child) -> void {
                const auto [decision, action] = func(ctx, child);
                if (decision == CheckDecision::INCORRECT) {
                    finalDecision = CheckDecision::INCORRECT;
                }
                if (action == CheckAction::SKIP_SUBTREE) {
                    return;
                }
                child->Iterate(aux);
            };
            aux(ast);
            return {finalDecision, CheckAction::CONTINUE};
        };
    }

    template <typename T>
    void AddInvariant(ArenaAllocator *allocator, const std::string &name)
    {
        auto check = *allocator->New<T>(*allocator);
        invariantsChecks_[name] = check;
        invariantsNames_.insert(name);
        invariantsChecks_[name + RECURSIVE_SUFFIX] = RecursiveInvariant(check);
        invariantsNames_.insert(name + RECURSIVE_SUFFIX);
    }

    Invariants invariantsChecks_;
    InvariantNameSet invariantsNames_;
};

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
