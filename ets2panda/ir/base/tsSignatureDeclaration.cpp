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

#include "tsSignatureDeclaration.h"

#include "binder/scope.h"
#include "ir/typeNode.h"
#include "ir/astDump.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"

#include "checker/TSchecker.h"

namespace panda::es2panda::ir {
void TSSignatureDeclaration::TransformChildren(const NodeTransformer &cb)
{
    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterDeclaration();
    }

    for (auto *&it : params_) {
        it = cb(it)->AsExpression();
    }

    if (return_type_annotation_ != nullptr) {
        return_type_annotation_ = static_cast<TypeNode *>(cb(return_type_annotation_));
    }
}

void TSSignatureDeclaration::Iterate(const NodeTraverser &cb) const
{
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

void TSSignatureDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", (kind_ == TSSignatureDeclaration::TSSignatureDeclarationKind::CALL_SIGNATURE)
                              ? "TSCallSignatureDeclaration"
                              : "TSConstructSignatureDeclaration"},
                 {"params", params_},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"returnType", AstDumper::Optional(return_type_annotation_)}});
}

void TSSignatureDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSSignatureDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    checker::ScopeContext scope_ctx(checker, scope_);

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(params_, signature_info);

    bool is_call_signature = (Kind() == ir::TSSignatureDeclaration::TSSignatureDeclarationKind::CALL_SIGNATURE);

    if (return_type_annotation_ == nullptr) {
        if (is_call_signature) {
            checker->ThrowTypeError(
                "Call signature, which lacks return-type annotation, implicitly has an 'any' return type.", Start());
        }

        checker->ThrowTypeError(
            "Construct signature, which lacks return-type annotation, implicitly has an 'any' return type.", Start());
    }

    return_type_annotation_->Check(checker);
    checker::Type *return_type = return_type_annotation_->GetType(checker);

    auto *signature = checker->Allocator()->New<checker::Signature>(signature_info, return_type);

    checker::Type *placeholder_obj = nullptr;

    if (is_call_signature) {
        placeholder_obj = checker->CreateObjectTypeWithCallSignature(signature);
    } else {
        placeholder_obj = checker->CreateObjectTypeWithConstructSignature(signature);
    }

    SetTsType(placeholder_obj);
    return placeholder_obj;
}

checker::Type *TSSignatureDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
