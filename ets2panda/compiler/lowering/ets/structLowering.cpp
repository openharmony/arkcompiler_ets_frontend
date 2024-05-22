/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "structLowering.h"
#include "checker/ETSchecker.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/astNode.h"
#include "ir/expression.h"
#include "ir/opaqueTypeNode.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/classDeclaration.h"
#include "ir/ts/tsAsExpression.h"
#include "type_helper.h"

namespace ark::es2panda::compiler {

const char *const STRUCT_CLASS_NAME = "CommonStruct0";

ir::ETSTypeReference *CreateStructTypeReference(checker::ETSChecker *checker,
                                                ir::ETSStructDeclaration *etsStrucDeclaration)
{
    auto *allocator = checker->Allocator();

    ArenaVector<ir::TypeNode *> params(allocator->Adapter());

    ir::TSTypeParameterInstantiation *typeParamSelfInst = nullptr;

    if (etsStrucDeclaration->Definition()->TypeParams() != nullptr &&
        !etsStrucDeclaration->Definition()->TypeParams()->Params().empty()) {
        ArenaVector<ir::TypeNode *> selfParams(allocator->Adapter());
        ir::ETSTypeReferencePart *referencePart = nullptr;

        for (const auto &param : etsStrucDeclaration->Definition()->TypeParams()->Params()) {
            auto *identRef = checker->AllocNode<ir::Identifier>(param->AsTSTypeParameter()->Name()->Name(), allocator);
            identRef->AsIdentifier()->SetReference();

            referencePart = checker->AllocNode<ir::ETSTypeReferencePart>(identRef, nullptr, nullptr);

            auto *typeReference = checker->AllocNode<ir::ETSTypeReference>(referencePart);

            selfParams.push_back(typeReference);
        }

        typeParamSelfInst = checker->AllocNode<ir::TSTypeParameterInstantiation>(std::move(selfParams));
    }

    auto *identSelfRef =
        checker->AllocNode<ir::Identifier>(etsStrucDeclaration->Definition()->Ident()->Name(), allocator);
    identSelfRef->AsIdentifier()->SetReference();

    auto *referenceSelfPart = checker->AllocNode<ir::ETSTypeReferencePart>(identSelfRef, typeParamSelfInst, nullptr);

    auto *selfTypeReference = checker->AllocNode<ir::ETSTypeReference>(referenceSelfPart);

    params.push_back(selfTypeReference);

    auto *typeParamInst = checker->AllocNode<ir::TSTypeParameterInstantiation>(std::move(params));

    auto *identRef = checker->AllocNode<ir::Identifier>(util::StringView(STRUCT_CLASS_NAME), allocator);
    identRef->AsIdentifier()->SetReference();
    auto *referencePart = checker->AllocNode<ir::ETSTypeReferencePart>(identRef, typeParamInst, nullptr);

    auto *typeReference = checker->AllocNode<ir::ETSTypeReference>(referencePart);

    return typeReference;
}

using AstNodePtr = ir::AstNode *;

bool StructLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    checker::ETSChecker *checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        [checker](ir::AstNode *ast) -> AstNodePtr {
            if (ast->IsETSStructDeclaration()) {
                auto *typeRef = CreateStructTypeReference(checker, ast->AsETSStructDeclaration());
                ast->AsETSStructDeclaration()->Definition()->SetSuper(typeRef);
                ast->AsETSStructDeclaration()->Definition()->AddModifier(ir::ModifierFlags::FINAL);
            }

            return ast;
        },
        Name());

    return true;
}

}  // namespace ark::es2panda::compiler
