/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "checker/ets/dynamic/dynamicCall.h"

#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/module/importSpecifier.h"
#include "ir/ts/tsQualifiedName.h"
#include "ir/expressions/memberExpression.h"

namespace ark::es2panda::checker {

DynamicCall::Result DynamicCall::ResolveCall(const varbinder::ETSBinder *varbinder, const ir::Expression *callee)
{
    auto calleeName = NameHolder(varbinder->Allocator()->Adapter());

    if (callee->IsETSTypeReference()) {
        // new A.B.C() => call js.new(A, ".B.C")
        callee = callee->AsETSTypeReference()->Part()->Name();
        while (callee->IsTSQualifiedName()) {
            auto *qname = callee->AsTSQualifiedName();
            callee = qname->Left();
            calleeName.emplace_back(qname->Right()->AsIdentifier()->Name());
        }
        ES2PANDA_ASSERT(callee->IsIdentifier());
    } else if (callee->IsMemberExpression()) {
        const auto memberExpr = callee->AsMemberExpression();
        callee = SqueezeExpr(memberExpr, calleeName);
    }
    if (callee->IsIdentifier()) {
        // kinda optimization in case:
        // `import X from Y` to use (load Y, call "X"), instead of (load Y, load X, call)
        const auto var = callee->AsIdentifier()->Variable();
        const auto *data = varbinder->DynamicImportDataForVar(var);
        if (data != nullptr && data->specifier != nullptr && data->specifier->IsImportSpecifier()) {
            calleeName.emplace_back(data->specifier->AsImportSpecifier()->Imported()->Name());
            std::reverse(calleeName.begin(), calleeName.end());
            return {data->import, calleeName};
        }
    }
    std::reverse(calleeName.begin(), calleeName.end());
    return {callee, calleeName};
}

DynamicCall::Result DynamicCall::SqueezeExpr(ArenaAllocator *allocator, const ir::MemberExpression *expr)
{
    NameHolder name(allocator->Adapter());
    auto obj = SqueezeExpr(expr, name);
    std::reverse(name.begin(), name.end());
    return {obj, name};
}

const ir::Expression *DynamicCall::SqueezeExpr(const ir::MemberExpression *memberExpr, NameHolder &name)
{
    if (!memberExpr->Object()->TsType()->IsETSDynamicType() || memberExpr->IsComputed()) {
        return memberExpr;
    }
    ES2PANDA_ASSERT(memberExpr->Property()->IsIdentifier());
    name.emplace_back(memberExpr->Property()->AsIdentifier()->Name());
    if (memberExpr->Object()->IsMemberExpression()) {
        return SqueezeExpr(memberExpr->Object()->AsMemberExpression(), name);
    }
    return memberExpr->Object();
}

}  // namespace ark::es2panda::checker
