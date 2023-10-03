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

#include "methodDefinition.h"

#include "binder/scope.h"
#include "ir/astDump.h"
#include "ir/base/decorator.h"
#include "ir/base/classDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/typeNode.h"
#include "checker/ETSchecker.h"

#include <utility>

namespace panda::es2panda::ir {

ScriptFunction *MethodDefinition::Function()
{
    return value_->AsFunctionExpression()->Function();
}

const ScriptFunction *MethodDefinition::Function() const
{
    return value_->AsFunctionExpression()->Function();
}

PrivateFieldKind MethodDefinition::ToPrivateFieldKind(bool is_static) const
{
    switch (kind_) {
        case MethodDefinitionKind::METHOD: {
            return is_static ? PrivateFieldKind::STATIC_METHOD : PrivateFieldKind::METHOD;
        }
        case MethodDefinitionKind::GET: {
            return is_static ? PrivateFieldKind::STATIC_GET : PrivateFieldKind::GET;
        }
        case MethodDefinitionKind::SET: {
            return is_static ? PrivateFieldKind::STATIC_SET : PrivateFieldKind::SET;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void MethodDefinition::Iterate(const NodeTraverser &cb) const
{
    cb(key_);
    cb(value_);

    for (auto *it : overloads_) {
        cb(it);
    }

    for (auto *it : decorators_) {
        cb(it);
    }
}

void MethodDefinition::Dump(ir::AstDumper *dumper) const
{
    const char *kind = nullptr;

    switch (kind_) {
        case MethodDefinitionKind::CONSTRUCTOR: {
            kind = "constructor";
            break;
        }
        case MethodDefinitionKind::METHOD: {
            kind = "method";
            break;
        }
        case MethodDefinitionKind::GET: {
            kind = "get";
            break;
        }
        case MethodDefinitionKind::SET: {
            kind = "set";
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    dumper->Add({{"type", "MethodDefinition"},
                 {"key", key_},
                 {"kind", kind},
                 {"accessibility", AstDumper::Optional(AstDumper::ModifierToString(flags_))},
                 {"static", IsStatic()},
                 {"optional", IsOptional()},
                 {"computed", is_computed_},
                 {"value", value_},
                 {"overloads", overloads_},
                 {"decorators", decorators_}});
}

void MethodDefinition::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void MethodDefinition::Compile([[maybe_unused]] compiler::ETSGen *etsg) const {}

checker::Type *MethodDefinition::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *MethodDefinition::Check(checker::ETSChecker *checker)
{
    auto *script_func = Function();

    if (script_func->IsProxy()) {
        return nullptr;
    }

    // TODO(aszilagyi): make it correctly check for open function not have body
    if (!script_func->HasBody() &&
        !(IsAbstract() || IsNative() || checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->ThrowTypeError("Only abstract or native methods can't have body", script_func->Start());
    }

    if (TsType() == nullptr) {
        SetTsType(checker->BuildMethodSignature(this));
    }

    CheckMethodModifiers(checker);

    if (IsNative() && script_func->ReturnTypeAnnotation() == nullptr) {
        checker->ThrowTypeError("'Native' method should have explicit return type", script_func->Start());
    }

    if (IsNative() && (script_func->IsGetter() || script_func->IsSetter())) {
        checker->ThrowTypeError("'Native' modifier is invalid for Accessors", script_func->Start());
    }

    if (script_func->IsAsyncFunc()) {
        auto *ret_type = static_cast<checker::ETSObjectType *>(script_func->Signature()->ReturnType());
        if (ret_type->AssemblerName() != checker->GlobalBuiltinPromiseType()->AssemblerName()) {
            checker->ThrowTypeError("Return type of async function must be 'Promise'", script_func->Start());
        }
    } else if (script_func->HasBody() && !script_func->IsExternal()) {
        if (IsNative() || IsAbstract()) {
            checker->ThrowTypeError("Native or Abstract methods cannot have body.", script_func->Body()->Start());
        }

        checker::ScopeContext scope_ctx(checker, script_func->Scope());
        checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
                                                   checker->Context().ContainingClass());
        checker->Context().SetContainingSignature(checker->GetSignatureFromMethodDefinition(this));

        if (IsStatic() && !IsConstructor() &&
            !checker->Context().ContainingClass()->HasObjectFlag(checker::ETSObjectFlags::GLOBAL)) {
            checker->AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
        }

        if (IsConstructor()) {
            checker->AddStatus(checker::CheckerStatus::IN_CONSTRUCTOR);
        }

        script_func->Body()->Check(checker);
        checker->Context().SetContainingSignature(nullptr);
    }

    checker->CheckOverride(TsType()->AsETSFunctionType()->FindSignature(Function()));

    for (auto *it : overloads_) {
        it->Check(checker);
    }

    if (script_func->IsRethrowing()) {
        checker->CheckRethrowingFunction(script_func);
    }

    return TsType();
}

void MethodDefinition::CheckMethodModifiers(checker::ETSChecker *checker)
{
    auto const not_valid_in_abstract = ir::ModifierFlags::NATIVE | ir::ModifierFlags::PRIVATE |
                                       ir::ModifierFlags::OVERRIDE | ir::ModifierFlags::FINAL |
                                       ir::ModifierFlags::STATIC;

    if (IsAbstract() && (flags_ & not_valid_in_abstract) != 0U) {
        checker->ThrowTypeError(
            "Invalid method modifier(s): an abstract method can't have private, override, static, final or native "
            "modifier.",
            Start());
    }

    if ((IsAbstract() || (!Function()->HasBody() && !IsNative())) &&
        !(checker->HasStatus(checker::CheckerStatus::IN_ABSTRACT) ||
          checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->ThrowTypeError("Non abstract class has abstract method.", Start());
    }

    auto const not_valid_in_final = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::STATIC | ir::ModifierFlags::NATIVE;

    if (IsFinal() && (flags_ & not_valid_in_final) != 0U) {
        checker->ThrowTypeError(
            "Invalid method modifier(s): a final method can't have abstract, static or native modifier.", Start());
    }

    auto const not_valid_in_static =
        ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::FINAL | ir::ModifierFlags::OVERRIDE;

    if (IsStatic() && (flags_ & not_valid_in_static) != 0U) {
        checker->ThrowTypeError(
            "Invalid method modifier(s): a static method can't have abstract, final or override modifier.", Start());
    }
}
}  // namespace panda::es2panda::ir
