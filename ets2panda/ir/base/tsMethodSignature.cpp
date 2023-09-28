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

#include "tsMethodSignature.h"

#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameter.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameterDeclaration.h"

#include "plugins/ecmascript/es2panda/checker/TSchecker.h"

namespace panda::es2panda::ir {
void TSMethodSignature::Iterate(const NodeTraverser &cb) const
{
    cb(key_);

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : params_) {
        cb(it);
    }

    if (return_type_annotation_ != nullptr) {
        cb(return_type_annotation_);
    }
}

void TSMethodSignature::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSMethodSignature"},
                 {"computed", computed_},
                 {"optional", optional_},
                 {"key", key_},
                 {"params", params_},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"typeAnnotation", AstDumper::Optional(return_type_annotation_)}});
}

void TSMethodSignature::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSMethodSignature::Check([[maybe_unused]] checker::TSChecker *checker)
{
    if (computed_) {
        checker->CheckComputedPropertyName(key_);
    }

    checker::ScopeContext scope_ctx(checker, scope_);

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(params_, signature_info);

    auto *call_signature = checker->Allocator()->New<checker::Signature>(signature_info, checker->GlobalAnyType());
    Variable()->SetTsType(checker->CreateFunctionTypeWithSignature(call_signature));

    if (return_type_annotation_ == nullptr) {
        checker->ThrowTypeError(
            "Method signature, which lacks return-type annotation, implicitly has an 'any' return type.", Start());
    }

    return_type_annotation_->Check(checker);
    call_signature->SetReturnType(return_type_annotation_->GetType(checker));

    return nullptr;
}

checker::Type *TSMethodSignature::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
