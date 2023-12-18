/*
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

#ifndef ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
#define ES2PANDA_COMPILER_CORE_ASTVERIFIER_H

#include <regex>
#include "ir/astNode.h"
#include "lexer/token/sourceLocation.h"
#include "parser/program/program.h"
#include "util/ustring.h"
#include "utils/arena_containers.h"
#include "varbinder/variable.h"
#include "utils/json_builder.h"
#include "ir/statements/blockStatement.h"
#include "compiler/lowering/phase.h"

namespace panda::es2panda::compiler {

/*
 * ASTVerifier used for checking various invariants that should hold during AST transformation in lowerings
 * For all available checks lookup the constructor
 */
class ASTVerifier final {
public:
    struct InvariantError {
        std::string cause;
        std::string message;
        size_t line;
    };
    struct CheckError {
        util::StringView invariantName;
        InvariantError error;

        std::function<void(JsonObjectBuilder &)> DumpJSON() const
        {
            return [&](JsonObjectBuilder &body) {
                body.AddProperty("invariant", invariantName.Utf8());
                body.AddProperty("cause", error.cause);
                body.AddProperty("message", error.message);
                body.AddProperty("line", error.line + 1);
            };
        }
    };
    using Errors = std::vector<CheckError>;

    enum class CheckResult { FAILED, SUCCESS, SKIP_SUBTREE };
    struct ErrorContext;
    using InvariantCheck = std::function<CheckResult(ErrorContext &ctx, const ir::AstNode *)>;
    struct Invariant {
        util::StringView invariantName;
        InvariantCheck invariant;
    };
    using Invariants = std::vector<Invariant>;

    NO_COPY_SEMANTIC(ASTVerifier);
    NO_MOVE_SEMANTIC(ASTVerifier);

    explicit ASTVerifier(ArenaAllocator *allocator);
    ~ASTVerifier() = default;

    using InvariantSet = std::set<std::string>;

    /**
     * @brief Run all existing invariants on some ast node (and consequently it's children)
     * @param ast AstNode which will be analyzed
     * @return Errors report of analysis
     */
    Errors VerifyFull(const ir::AstNode *ast);

    /**
     * @brief Run some particular invariants on some ast node
     * @note invariants must be supplied as strings to invariant_set, additionally invariant
     * name can be suffixed by `ForAll` string to include recursive analysis of provided node
     * I.e. 'HasParent' invariant can be named 'HasParentRecursive' to traverse all child nodes as well
     * @param ast AstNode which will be analyzed
     * @param invariant_set Set of strings which will be used as invariant names
     * @return Errors report of analysis
     */
    Errors Verify(const ir::AstNode *ast, const InvariantSet &invariantSet);

private:
    Invariants invariantsChecks_;
    InvariantSet invariantsNames_;
};

class ASTVerifierContext final {
public:
    ASTVerifierContext(ASTVerifier &verifier) : verifier_ {verifier} {}

    void IntroduceNewInvariants(util::StringView phaseName)
    {
        auto invariantSet = [phaseName]() -> std::optional<ASTVerifier::InvariantSet> {
            (void)phaseName;
            if (phaseName == "ScopesInitPhase") {
                return {{
                    "NodeHasParentForAll",
                    "IdentifierHasVariableForAll",
                    "ModifierAccessValidForAll",
                    "ImportExportAccessValid",
                }};
            } else if (phaseName == "PromiseVoidInferencePhase") {
                return {{}};
            } else if (phaseName == "StructLowering") {
                return {{}};
            } else if (phaseName == "CheckerPhase") {
                return {{
                    "NodeHasTypeForAll",
                    "ArithmeticOperationValidForAll",
                    "SequenceExpressionHasLastTypeForAll",
                    "EveryChildHasValidParentForAll",
                    "ForLoopCorrectlyInitializedForAll",
                    "VariableHasScopeForAll",
                    "VariableHasEnclosingScopeForAll",
                }};
            } else if (phaseName == "GenerateTsDeclarationsPhase") {
                return {{}};
            } else if (phaseName == "InterfacePropertyDeclarationsPhase") {
                return {{}};
            } else if (phaseName == "LambdaConstructionPhase") {
                return {{}};
            } else if (phaseName == "ObjectIndexLowering") {
                return {{}};
            } else if (phaseName == "OpAssignmentLowering") {
                return {{}};
            } else if (phaseName == "PromiseVoidInferencePhase") {
                return {{}};
            } else if (phaseName == "TupleLowering") {
                return {{}};
            } else if (phaseName == "UnionLowering") {
                return {{}};
            } else if (phaseName == "ExpandBracketsPhase") {
                return {{}};
            } else if (phaseName.Utf8().find("plugins") != std::string_view::npos) {
                return {{}};
            }
            return std::nullopt;
        }();

        ASSERT_PRINT(invariantSet.has_value(),
                     std::string {"Invariant set does not contain value for "} + phaseName.Mutf8());
        const auto &s = *invariantSet;
        accumulatedChecks_.insert(s.begin(), s.end());
    }

    bool Verify(const ir::AstNode *ast, util::StringView phaseName, util::StringView sourceName)
    {
        errors_ = verifier_.Verify(ast, accumulatedChecks_);
        for (const auto &e : errors_) {
            errorArray_.Add([e, sourceName, phaseName](JsonObjectBuilder &err) {
                err.AddProperty("from", sourceName.Utf8());
                err.AddProperty("phase", phaseName.Utf8());
                err.AddProperty("error", e.DumpJSON());
            });
        }
        auto result = errors_.empty();
        errors_.clear();
        return result;
    }

    std::string DumpErrorsJSON()
    {
        return std::move(errorArray_).Build();
    }

private:
    ASTVerifier &verifier_;
    ASTVerifier::Errors errors_;
    JsonArrayBuilder errorArray_;
    ASTVerifier::InvariantSet accumulatedChecks_ {};
};

}  // namespace panda::es2panda::compiler

#endif  // ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
