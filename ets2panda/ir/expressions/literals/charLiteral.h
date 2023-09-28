/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "plugins/ecmascript/es2panda/ir/expressions/literal.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"

namespace panda::es2panda::ir {
class CharLiteral : public Literal {
public:
    explicit CharLiteral() : CharLiteral(u'\u0000') {}
    explicit CharLiteral(char16_t character) : Literal(AstNodeType::CHAR_LITERAL), char_(character) {}

    char16_t Char() const
    {
        return char_;
    }

    bool operator==(const CharLiteral &other) const
    {
        return char_ == other.char_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    char16_t char_;
};
}  // namespace panda::es2panda::ir

#endif
