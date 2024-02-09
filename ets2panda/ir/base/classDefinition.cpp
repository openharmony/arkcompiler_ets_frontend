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

#include "classDefinition.h"

#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsClassImplements.h"

namespace ark::es2panda::ir {
const FunctionExpression *ClassDefinition::Ctor() const
{
    return ctor_ != nullptr ? ctor_->Value()->AsFunctionExpression() : nullptr;
}

bool ClassDefinition::HasPrivateMethod() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsMethodDefinition() && element->AsClassElement()->IsPrivateElement();
    });
}

bool ClassDefinition::HasComputedInstanceField() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsClassProperty() && element->AsClassElement()->IsComputed() &&
               !(element->AsClassElement()->Modifiers() & ir::ModifierFlags::STATIC);
    });
}

bool ClassDefinition::HasMatchingPrivateKey(const util::StringView &name) const
{
    return std::any_of(body_.cbegin(), body_.cend(), [&name](auto *element) {
        return element->AsClassElement()->IsPrivateElement() && element->AsClassElement()->Id()->Name() == name;
    });
}

void ClassDefinition::TransformChildren(const NodeTransformer &cb)
{
    if (ident_ != nullptr) {
        ident_ = cb(ident_)->AsIdentifier();
    }

    if (typeParams_ != nullptr) {
        typeParams_ = cb(typeParams_)->AsTSTypeParameterDeclaration();
    }

    if (superClass_ != nullptr) {
        superClass_ = cb(superClass_)->AsExpression();
    }

    if (superTypeParams_ != nullptr) {
        superTypeParams_ = cb(superTypeParams_)->AsTSTypeParameterInstantiation();
    }

    for (auto *&it : implements_) {
        it = cb(it)->AsTSClassImplements();
    }

    if (ctor_ != nullptr) {
        ctor_ = cb(ctor_)->AsMethodDefinition();
    }

    for (auto *&it : body_) {
        it = cb(it);
    }
}

void ClassDefinition::Iterate(const NodeTraverser &cb) const
{
    if (ident_ != nullptr) {
        cb(ident_);
    }

    if (typeParams_ != nullptr) {
        cb(typeParams_);
    }

    if (superClass_ != nullptr) {
        cb(superClass_);
    }

    if (superTypeParams_ != nullptr) {
        cb(superTypeParams_);
    }

    for (auto *it : implements_) {
        cb(it);
    }

    if (ctor_ != nullptr) {
        cb(ctor_);
    }

    for (auto *it : body_) {
        cb(it);
    }
}

void ClassDefinition::Dump(ir::AstDumper *dumper) const
{
    auto propFilter = [](AstNode *prop) -> bool {
        return !prop->IsClassStaticBlock() || !prop->AsClassStaticBlock()->Function()->IsHidden();
    };
    dumper->Add({{"id", AstDumper::Nullish(ident_)},
                 {"typeParameters", AstDumper::Optional(typeParams_)},
                 {"superClass", AstDumper::Nullish(superClass_)},
                 {"superTypeParameters", AstDumper::Optional(superTypeParams_)},
                 {"implements", implements_},
                 {"constructor", AstDumper::Optional(ctor_)},
                 {"body", body_, propFilter}});
}

void ClassDefinition::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(ident_ != nullptr);

    if (IsExtern()) {
        dumper->Add("extern ");
    }

    if (IsFinal()) {
        dumper->Add("final ");
    }

    if (IsAbstract()) {
        dumper->Add("abstract ");
    }

    dumper->Add("class ");
    ident_->Dump(dumper);

    if (typeParams_ != nullptr) {
        dumper->Add("<");
        typeParams_->Dump(dumper);
        dumper->Add("> ");
    }

    if (superClass_ != nullptr) {
        dumper->Add(" extends ");
        superClass_->Dump(dumper);
    }

    if (!implements_.empty()) {
        dumper->Add(" implements ");
        for (auto interface : implements_) {
            interface->Dump(dumper);
            if (interface != implements_.back()) {
                dumper->Add(", ");
            }
        }
    }

    dumper->Add(" {");
    if (!body_.empty()) {
        dumper->IncrIndent();
        dumper->Endl();
        for (auto elem : body_) {
            elem->Dump(dumper);
            if (elem == body_.back()) {
                dumper->DecrIndent();
            }
            dumper->Endl();
        }
    }
    dumper->Add("}");
    dumper->Endl();
}

void ClassDefinition::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ClassDefinition::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ClassDefinition::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ClassDefinition::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace ark::es2panda::ir
