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

#include "templateLiteral.h"

#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/base/templateElement.h"

namespace panda::es2panda::ir {
void TemplateLiteral::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : expressions_) {
        it = cb(it)->AsExpression();
    }

    for (auto *&it : quasis_) {
        it = cb(it)->AsTemplateElement();
    }
}

void TemplateLiteral::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : expressions_) {
        cb(it);
    }

    for (auto *it : quasis_) {
        cb(it);
    }
}

void TemplateLiteral::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TemplateLiteral"}, {"expressions", expressions_}, {"quasis", quasis_}});
}

void TemplateLiteral::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    auto quasis_it = quasis_.begin();
    auto expression_it = expressions_.begin();

    pg->LoadAccumulatorString(this, (*quasis_it)->Raw());

    quasis_it++;

    bool is_quais = false;
    size_t total = quasis_.size() + expressions_.size();

    compiler::RegScope rs(pg);
    compiler::VReg lhs = pg->AllocReg();

    while (total != 1) {
        const ir::AstNode *node = nullptr;

        if (is_quais) {
            pg->StoreAccumulator(*quasis_it, lhs);
            pg->LoadAccumulatorString(this, (*quasis_it)->Raw());

            node = *quasis_it;
            quasis_it++;
        } else {
            const ir::Expression *element = *expression_it;
            pg->StoreAccumulator(element, lhs);

            element->Compile(pg);

            node = element;
            expression_it++;
        }

        pg->Binary(node, lexer::TokenType::PUNCTUATOR_PLUS, lhs);

        is_quais = !is_quais;
        total--;
    }
}

checker::Type *TemplateLiteral::Check([[maybe_unused]] checker::TSChecker *checker)
{
    // TODO(aszilagyi)
    return checker->GlobalAnyType();
}

void TemplateLiteral::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->BuildTemplateString(this);
}

checker::Type *TemplateLiteral::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    if (quasis_.size() != expressions_.size() + 1U) {
        checker->ThrowTypeError("Invalid string template expression", this->Start());
    }

    for (auto *it : expressions_) {
        it->Check(checker);
    }

    for (auto *it : quasis_) {
        it->Check(checker);
    }

    SetTsType(checker->GlobalBuiltinETSStringType());
    return TsType();
}
}  // namespace panda::es2panda::ir
