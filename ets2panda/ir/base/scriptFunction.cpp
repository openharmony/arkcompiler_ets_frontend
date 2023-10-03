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

#include "scriptFunction.h"

#include "binder/scope.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/expression.h"
#include "ir/typeNode.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/blockStatement.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"

namespace panda::es2panda::ir {
bool ScriptFunction::HasBody() const
{
    return body_ != nullptr;
}

ir::ScriptFunctionFlags ScriptFunction::Flags() const
{
    return func_flags_;
}

size_t ScriptFunction::FormalParamsLength() const
{
    size_t length = 0;

    for (const auto *param : params_) {
        if (param->IsRestElement() || param->IsAssignmentPattern()) {
            break;
        }

        length++;
    }

    return length;
}

void ScriptFunction::Iterate(const NodeTraverser &cb) const
{
    if (id_ != nullptr) {
        cb(id_);
    }

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : params_) {
        cb(it);
    }

    if (return_type_annotation_ != nullptr) {
        cb(return_type_annotation_);
    }

    if (body_ != nullptr) {
        cb(body_);
    }
}

void ScriptFunction::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ScriptFunction"},
                 {"id", AstDumper::Nullable(id_)},
                 {"generator", IsGenerator()},
                 {"async", IsAsyncFunc()},
                 {"expression", ((func_flags_ & ir::ScriptFunctionFlags::EXPRESSION) != 0)},
                 {"params", params_},
                 {"returnType", AstDumper::Optional(return_type_annotation_)},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"declare", AstDumper::Optional(declare_)},
                 {"body", AstDumper::Optional(body_)}});

    if (IsThrowing()) {
        dumper->Add({"throwMarker", "throws"});
    } else if (IsRethrowing()) {
        dumper->Add({"throwMarker", "rethrows"});
    }
}

void ScriptFunction::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}
void ScriptFunction::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *ScriptFunction::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ScriptFunction::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
