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

#include "tsConstructorType.h"

#include "binder/scope.h"
#include "checker/TSchecker.h"
#include "checker/types/signature.h"
#include "ir/astDump.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"

namespace panda::es2panda::ir {
void TSConstructorType::TransformChildren(const NodeTransformer &cb)
{
    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterDeclaration();
    }

    for (auto *&it : params_) {
        it = cb(it)->AsExpression();
    }

    return_type_ = static_cast<TypeNode *>(cb(return_type_));
}

void TSConstructorType::Iterate(const NodeTraverser &cb) const
{
    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : params_) {
        cb(it);
    }

    cb(return_type_);
}

void TSConstructorType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSConstructorType"},
                 {"params", params_},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"returnType", return_type_},
                 {"abstract", AstDumper::Optional(abstract_)}});
}

void TSConstructorType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSConstructorType::Check(checker::TSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, scope_);

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(params_, signature_info);
    return_type_->Check(checker);
    auto *construct_signature =
        checker->Allocator()->New<checker::Signature>(signature_info, return_type_->GetType(checker));

    return checker->CreateConstructorTypeWithSignature(construct_signature);
}

checker::Type *TSConstructorType::GetType(checker::TSChecker *checker)
{
    return checker->CheckTypeCached(this);
}

checker::Type *TSConstructorType::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
