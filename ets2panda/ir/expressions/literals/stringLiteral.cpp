/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "stringLiteral.h"
#include <cstddef>

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "macros.h"

namespace panda::es2panda::ir {
void StringLiteral::TransformChildren([[maybe_unused]] const NodeTransformer &cb) {}
void StringLiteral::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void StringLiteral::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "StringLiteral"}, {"value", str_}});
}

void StringLiteral::Dump(ir::SrcDumper *dumper) const
{
    std::string str(str_);
    std::string escaped_str;
    escaped_str.push_back('\"');
    for (size_t i = 0, j = str_.Length(); i < j; ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const char c = str_.Bytes()[i];
        // check if a given character is printable
        // the cast is necessary to avoid undefined behaviour
        if (std::isprint(static_cast<unsigned char>(c)) != 0U) {
            escaped_str.push_back(c);
        } else {
            escaped_str.push_back('\\');
            if (c == '\n') {
                escaped_str.push_back('n');
            } else if (c == '\t') {
                escaped_str.push_back('t');
            } else if (c == '\v') {
                escaped_str.push_back('v');
            } else if (c == '\f') {
                escaped_str.push_back('f');
            } else if (c == '\r') {
                escaped_str.push_back('r');
            } else if (c == '\0') {
                escaped_str.push_back('0');
            } else {
                UNREACHABLE();
            }
        }
    }
    escaped_str.push_back('\"');
    dumper->Add(escaped_str);
}

void StringLiteral::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void StringLiteral::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *StringLiteral::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *StringLiteral::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

// NOLINTNEXTLINE(google-default-arguments)
StringLiteral *StringLiteral::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<StringLiteral>(str_); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
