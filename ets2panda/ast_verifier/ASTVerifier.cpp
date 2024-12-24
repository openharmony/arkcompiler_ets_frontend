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
                                        << util::gen::ast_verifier::ToString(VerifierInvariants {i}));
                }

                (*astCorrect) &= ((decisions[inv.ID] == CheckDecision::CORRECT) && ...);
            },
            verifier->invariants_);

        node->Iterate(*this);
        verifier->enabled_ = enabledSave;
    }
};

static auto ExtractAst(const parser::Program &program, bool checkFullProgram)
{
    auto *allocator = program.Allocator();
    auto astToCheck = AstToCheck {allocator->Adapter()};
    astToCheck.insert(std::make_pair(program.SourceFilePath().Utf8(), program.Ast()));
    if (checkFullProgram) {
        for (const auto &externalSource : program.ExternalSources()) {
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
    if (suppressed_) {
        return;
    }
    auto astToCheck = ExtractAst(program_, options_.IsAstVerifierFullProgram());
    for (const auto &p : astToCheck) {
        const auto sourceName = p.first;
        const auto *ast = p.second;
        std::apply([](auto &&...inv) { ((inv.Init()), ...); }, invariants_);

        LOG_ASTV(INFO, "Begin traversal (" << sourceName << ')');

        bool astCorrect = true;
        // `const_cast` due to `ir::NodeTraverser` signature:
        SinglePassVerifier {this, &astCorrect}(const_cast<ir::AstNode *>(ast));

        auto reporter = [this, sourceName](auto &&inv) {
            if (inv.HasMessages()) {
                report_.back().second[sourceName][TreatAsError(inv.ID) ? "errors" : "warnings"][inv.ID] =
                    std::forward<CheckContext>(inv).MoveMessages();
                (TreatAsError(inv.ID) ? hasErrors_ : hasWarnings_) = true;
            }
        };
        ASSERT(astCorrect == std::apply([](const auto &...inv) { return ((!inv.HasMessages()) && ...); }, invariants_));
        if (!astCorrect) {
            if (report_.empty() || report_.back().first != phaseName) {
                report_.emplace_back();
                report_.back().first = phaseName;
            }
            std::apply([&reporter](auto &...inv) { (reporter(std::move(inv)), ...); }, invariants_);
        }
    }
}

template <typename K, typename V>
void JsonAddProperty(JsonObjectBuilder &outer, K k, const V &v)
{
    outer.AddProperty(k, [&v](JsonObjectBuilder &inner) {
        for (const auto &[kInner, vInner] : v) {
            JsonAddProperty(inner, kInner, vInner);
        }
    });
}

template <>
void JsonAddProperty<VerifierInvariants, Messages>(JsonObjectBuilder &outer, VerifierInvariants k, const Messages &v)
{
    outer.AddProperty(util::gen::ast_verifier::ToString(k), [&v](JsonArrayBuilder &msgsBuilder) {
        for (const auto &msg : v) {
            msgsBuilder.Add(msg.DumpJSON());
        }
    });
}

void DumpJson(const ASTVerifier::GroupedMessages &report, const std::string &filePath)
{
    JsonObjectBuilder reportJson {};
    for (const auto &[phase, sourceMessages] : report) {
        JsonAddProperty(reportJson, phase, sourceMessages);
    }
    auto str = std::move(reportJson).Build();
    std::ofstream(filePath, std::ios::trunc | std::ios::out).write(str.data(), str.size());
}

template <bool IS_WARNING>
void DumpLogMessage(VerifierInvariants id, const Messages &msgs)
{
    auto invaraintName = util::gen::ast_verifier::ToString(id);
    if constexpr (IS_WARNING) {
        LOG(WARNING, ES2PANDA) << "    " << invaraintName << ':';
    } else {
        LOG(ERROR, ES2PANDA) << "    " << invaraintName << ':';
    }

    for (const auto &msg : msgs) {
        if constexpr (IS_WARNING) {
            LOG(WARNING, ES2PANDA) << "      " << msg.ToString();
        } else {
            LOG(ERROR, ES2PANDA) << "      " << msg.ToString();
        }
    }
}

template <Logger::Level LEVEL>
void DumpLogAstMessages(std::string_view path, const ASTVerifier::WarningsErrors &astMessages)
{
    static_assert((LEVEL == Logger::Level::WARNING) || (LEVEL == Logger::Level::ERROR));
    constexpr bool IS_WARNING = LEVEL == Logger::Level::WARNING;

    auto severityStr = IS_WARNING ? "warnings" : "errors";
    if (astMessages.find(severityStr) != astMessages.end()) {
        if constexpr (IS_WARNING) {
            LOG(WARNING, ES2PANDA) << "  In " << path << ':';
        } else {
            LOG(ERROR, ES2PANDA) << "  In " << path << ':';
        }
        for (const auto &[invaraintId, messages] : astMessages.at(severityStr)) {
            DumpLogMessage<IS_WARNING>(invaraintId, messages);
        }
    }
}

void DumpLog(const ASTVerifier::GroupedMessages &report)
{
    for (const auto &[phase, sourceMessages] : report) {
        LOG(WARNING, ES2PANDA) << "After " << phase << ':';
        for (const auto &[path, astMessages] : sourceMessages) {
            DumpLogAstMessages<Logger::Level::WARNING>(path, astMessages);
            DumpLogAstMessages<Logger::Level::ERROR>(path, astMessages);
        }
    }
}

void ASTVerifier::DumpMessages() const
{
    std::string errMsg = "ASTVerifier found broken invariants.";
    if (options_.IsAstVerifierJson()) {
        DumpJson(report_, options_.GetAstVerifierJsonPath());
        errMsg += " Dumped to '" + std::string(options_.GetAstVerifierJsonPath()) + "'.";
    } else {
        DumpLog(report_);
        errMsg += " You may want to pass '--ast-verifier:json' option for more verbose output.";
    }

    if (hasErrors_) {
        LOG(FATAL, ES2PANDA) << errMsg;
    } else if (hasWarnings_) {
        LOG(WARNING, ES2PANDA) << errMsg;
    }
}

void CheckContext::AddCheckMessage(const std::string &cause, const ir::AstNode &node)
{
    messages_.emplace_back(cause.data(), &node);
}

}  // namespace ark::es2panda::compiler::ast_verifier
