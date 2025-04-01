/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_EXPRESSION_LITERAL_CHAR_LITERAL_H
#define ES2PANDA_IR_EXPRESSION_LITERAL_CHAR_LITERAL_H

#include "ir/expressions/literal.h"
#include "util/ustring.h"

namespace ark::es2panda::ir {
class CharLiteral : public Literal {
public:
    ~CharLiteral() override = default;

    NO_COPY_SEMANTIC(CharLiteral);
    NO_MOVE_SEMANTIC(CharLiteral);

    explicit CharLiteral() : CharLiteral(u'\u0000') {}
    explicit CharLiteral(char16_t const character) : Literal(AstNodeType::CHAR_LITERAL), char_(character) {}

    [[nodiscard]] char16_t Char() const noexcept
    {
        return char_;
    }

    bool operator==(const CharLiteral &other) const
    {
        return char_ == other.char_;
    }

    [[nodiscard]] CharLiteral *Clone(ArenaAllocator *allocator, AstNode *parent) override;

    void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::VerifiedType Check([[maybe_unused]] checker::ETSChecker *checker) override;
    std::string ToString() const override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    char16_t const char_;
};
}  // namespace ark::es2panda::ir

#endif
