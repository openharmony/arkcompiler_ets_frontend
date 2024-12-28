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

#include "ASTVerifier.h"

namespace ark::es2panda::compiler::ast_verifier {

using AstToCheck = ArenaMap<ASTVerifier::SourcePath, const ir::AstNode *>;

struct ASTVerifier::SinglePassVerifier {
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ASTVerifier *verifier {nullptr};
    bool *astCorrect;
    // NOLINTEND(misc-non-private-member-variables-in-classes)

    void operator()(ir::AstNode *ncnode) const
    {
        const auto *node = ncnode;
        auto enabledSave = verifier->enabled_;
        LOG_ASTV(DEBUG, "Verify: " << node->DumpJSON());

        std::apply(
            [this, node](auto &...inv) {
                InvArray<CheckDecision> decisions {};
                InvArray<CheckAction> actions {};
                ((std::tie(decisions[inv.ID], actions[inv.ID]) =
                      verifier->NeedCheckInvariant(inv)
                          ? inv.VerifyNode(node)
                          : CheckResult {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE}),
                 ...);
                // Temporaly disable invariant, the value should be restored after node and its childs are visited:
                ((verifier->enabled_[inv.ID] &= (actions[inv.ID] == CheckAction::CONTINUE)), ...);

                for (size_t i = 0; i < VerifierInvariants::COUNT; i++) {
                    LOG_ASTV(DEBUG, (actions[i] == CheckAction::CONTINUE ? "Enabled " : "Disabled ")
                                        << util::gen::verifier_invariants::ToString(VerifierInvariants {i}));
                }

                (*astCorrect) &= ((decisions[inv.ID] == CheckDecision::CORRECT) && ...);
            },
            verifier->invariants_);

        node->Iterate(*this);
        verifier->enabled_ = enabledSave;
    }
};

static auto ExtractAst(const parser::Program *program, bool checkFullProgram)
{
    ASSERT(program != nullptr);
    auto &allocator = *program->Allocator();
    auto astToCheck = AstToCheck {allocator.Adapter()};
    astToCheck.insert(std::make_pair(program->SourceFilePath().Utf8(), program->Ast()));
    if (checkFullProgram) {
        for (const auto &externalSource : program->ExternalSources()) {
            for (auto *external : externalSource.second) {
                ASSERT(external->Ast() != nullptr);
                astToCheck.insert(std::make_pair(external->SourceFilePath().Utf8(), external->Ast()));
            }
        }
    }
    return astToCheck;
}

void ASTVerifier::Verify(std::string_view phaseName)
{
    auto astToCheck = ExtractAst(program_, options_->IsVerifierInvariantsFullProgram());
    for (const auto &p : astToCheck) {
        const auto sourceName = p.first;
        const auto *ast = p.second;
        std::apply([](auto &&...inv) { ((inv.Init()), ...); }, invariants_);

        LOG_ASTV(DEBUG, "Begin traversal (" << sourceName << ')');

        bool astCorrect = true;
        // `const_cast` due to `ir::NodeTraverser` signature:
        SinglePassVerifier {this, &astCorrect}(const_cast<ir::AstNode *>(ast));

        LOG_ASTV(DEBUG, "End traversal " << sourceName);

        auto reporter = [this, phaseName, sourceName](auto &&inv) {
            if (inv.HasMessages()) {
                report_[phaseName][sourceName][TreatAsError(inv.ID) ? "errors" : "warnings"][inv.NAME] =
                    std::forward<CheckContext>(inv).MoveMessages();
                (TreatAsError(inv.ID) ? hasErrors_ : hasWarnings_) = true;
            }
        };
        if (!astCorrect) {
            std::apply([&reporter](auto &...inv) { (reporter(std::move(inv)), ...); }, invariants_);
        }
    }
}

template <typename T>
void AddProperty(JsonObjectBuilder &outer, std::string_view k, const T &v)
{
    outer.AddProperty(k, [&v](JsonObjectBuilder &inner) {
        for (const auto &[kInner, vInner] : v) {
            AddProperty(inner, kInner, vInner);
        }
    });
}

template <>
void AddProperty<Messages>(JsonObjectBuilder &outer, std::string_view k, const Messages &v)
{
    outer.AddProperty(k, [&v](JsonArrayBuilder &msgsBuilder) {
        for (const auto &msg : v) {
            msgsBuilder.Add(msg.DumpJSON());
        }
    });
}

void ASTVerifier::DumpMessages() const
{
    JsonObjectBuilder reportJson {};
    for (const auto &[phase, sourceMessages] : report_) {
        AddProperty(reportJson, phase, sourceMessages);
    }

    if (hasErrors_) {
        LOG(FATAL, ES2PANDA) << "ASTVerifier found broken invariants:\n" << std::move(reportJson).Build();
    } else if (hasWarnings_) {
        LOG(WARNING, ES2PANDA) << "ASTVerifier found broken invariants:\n" << std::move(reportJson).Build();
    }
}

}  // namespace ark::es2panda::compiler::ast_verifier
