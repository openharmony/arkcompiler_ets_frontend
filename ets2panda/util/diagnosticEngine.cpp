/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "diagnosticEngine.h"
#include <memory>
#include "util/diagnostic.h"
#include "util/options.h"

#include <csignal>

namespace ark::es2panda {
std::pair<const parser::Program *, lexer::SourcePosition> GetPositionForDiagnostic()
{
    return {nullptr, lexer::SourcePosition {}};
}
}  // namespace ark::es2panda

namespace ark::es2panda::util {

void CLIDiagnosticPrinter::Print(const DiagnosticBase &diagnostic) const
{
    std::cout << DiagnosticTypeToString(diagnostic.Type()) << ": " << diagnostic.Message();
    if (!diagnostic.File().empty()) {
        std::cout << " [" << util::BaseName(diagnostic.File()) << ":" << diagnostic.Line() << ":" << diagnostic.Offset()
                  << "]";
    }
    std::cout << std::endl;
}

const DiagnosticStorage &DiagnosticEngine::GetDiagnosticStorage(DiagnosticType type)
{
    return diagnostics_[type];
}

[[noreturn]] void DiagnosticEngine::Throw(ThrowableDiagnostic diag) const
{
    throw diag;
}

DiagnosticStorage DiagnosticEngine::GetAllDiagnostic()
{
    size_t totalSize = 0;
    for (const auto &vec : diagnostics_) {
        totalSize += vec.size();
    }

    DiagnosticStorage merged;
    merged.reserve(totalSize);
    for (auto &vec : diagnostics_) {
        for (auto &&diag : vec) {
            merged.emplace_back(std::move(diag));
        }
    }
    return merged;
}

void DiagnosticEngine::FlushDiagnostic()
{
    auto log = GetAllDiagnostic();
    std::sort(log.begin(), log.end(), [](const auto &lhs, const auto &rhs) { return *lhs < *rhs; });
    auto last = std::unique(log.begin(), log.end());
    for (auto it = log.begin(); it != last; it++) {
        printer_->Print(**it);
    }
}

static void SigSegvHandler([[maybe_unused]] int sig)
{
    if (g_diagnosticEngine != nullptr) {
        g_diagnosticEngine->FlushDiagnostic();
    }
    std::cerr << "PLEASE submit a bug report to https://gitee.com/openharmony/arkcompiler_ets_frontend/issues"
              << std::endl;
    ark::PrintStack(ark::GetStacktrace(), std::cerr);
    std::abort();  // CC-OFF(G.STD.16-CPP) fatal error
}

void DiagnosticEngine::InitializeSignalHandlers()
{
    std::signal(SIGSEGV, SigSegvHandler);
}

bool DiagnosticEngine::IsAnyError() const noexcept
{
    for (size_t i = DiagnosticType::BEGIN; i < DiagnosticType::COUNT; ++i) {
        if (IsError(static_cast<DiagnosticType>(i)) && !diagnostics_[i].empty()) {
            return true;
        }
    }
    return false;
}

const DiagnosticBase &DiagnosticEngine::GetAnyError() const
{
    ASSERT(IsAnyError());
    for (size_t i = DiagnosticType::BEGIN; i < DiagnosticType::COUNT; ++i) {
        if (IsError(static_cast<DiagnosticType>(i)) && !diagnostics_[i].empty()) {
            return *diagnostics_[i].front();
        }
    }
    UNREACHABLE();
}

bool DiagnosticEngine::IsError(DiagnosticType type) const
{
    switch (type) {
        case DiagnosticType::FATAL:
        case DiagnosticType::SYNTAX:
        case DiagnosticType::SEMANTIC:
        case DiagnosticType::PLUGIN:
        case DiagnosticType::DECLGEN_ETS2TS_ERROR:
        case DiagnosticType::COMPILER_BUG:
            return true;
        case DiagnosticType::WARNING:
        case DiagnosticType::DECLGEN_ETS2TS_WARNING:
            return wError_;
        default:
            UNREACHABLE();
    }
}

}  // namespace ark::es2panda::util
