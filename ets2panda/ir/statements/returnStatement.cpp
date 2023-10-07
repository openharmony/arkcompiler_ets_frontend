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

#include "returnStatement.h"

#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/types/typeRelation.h"
#include "ir/astDump.h"
#include "ir/typeNode.h"
#include "ir/expression.h"
#include "ir/expressions/objectExpression.h"
#include "util/helpers.h"

namespace panda::es2panda::ir {
void ReturnStatement::TransformChildren(const NodeTransformer &cb)
{
    if (argument_ != nullptr) {
        argument_ = cb(argument_)->AsExpression();
    }
}

void ReturnStatement::Iterate(const NodeTraverser &cb) const
{
    if (argument_ != nullptr) {
        cb(argument_);
    }
}

void ReturnStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ReturnStatement"}, {"argument", AstDumper::Nullable(argument_)}});
}

void ReturnStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    if (argument_ != nullptr) {
        argument_->Compile(pg);
    } else {
        pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
    }

    if (pg->CheckControlFlowChange()) {
        compiler::RegScope rs(pg);
        compiler::VReg res = pg->AllocReg();

        pg->StoreAccumulator(this, res);
        pg->ControlFlowChangeBreak();
        pg->LoadAccumulator(this, res);
    }

    if (argument_ != nullptr) {
        pg->ValidateClassDirectReturn(this);
        pg->DirectReturn(this);
    } else {
        pg->ImplicitReturn(this);
    }
}

void ReturnStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    if (argument_ == nullptr) {
        if (return_type_ == nullptr || return_type_->IsETSVoidType()) {
            if (etsg->ExtendWithFinalizer(parent_, this)) {
                return;
            }

            if (etsg->CheckControlFlowChange()) {
                etsg->ControlFlowChangeBreak();
            }
            etsg->EmitReturnVoid(this);
            return;
        }

        etsg->LoadBuiltinVoid(this);

    } else {
        auto ttctx = compiler::TargetTypeContext(etsg, etsg->ReturnType());

        if (!etsg->TryLoadConstantExpression(argument_)) {
            argument_->Compile(etsg);
        }
    }

    if (etsg->ExtendWithFinalizer(parent_, this)) {
        return;
    }

    if (etsg->CheckControlFlowChange()) {
        compiler::RegScope rs(etsg);
        compiler::VReg res = etsg->AllocReg();

        etsg->StoreAccumulator(this, res);
        etsg->ControlFlowChangeBreak();
        etsg->LoadAccumulator(this, res);
    }

    etsg->ApplyConversion(this, return_type_);
    etsg->ReturnAcc(this);
}

checker::Type *ReturnStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    ir::AstNode *ancestor = util::Helpers::FindAncestorGivenByType(this, ir::AstNodeType::SCRIPT_FUNCTION);
    ASSERT(ancestor && ancestor->IsScriptFunction());
    auto *containing_func = ancestor->AsScriptFunction();

    if (containing_func->Parent()->Parent()->IsMethodDefinition()) {
        const ir::MethodDefinition *containing_class_method = containing_func->Parent()->Parent()->AsMethodDefinition();
        if (containing_class_method->Kind() == ir::MethodDefinitionKind::SET) {
            checker->ThrowTypeError("Setters cannot return a value", Start());
        }
    }

    if (containing_func->ReturnTypeAnnotation() != nullptr) {
        checker::Type *return_type = checker->GlobalUndefinedType();
        checker::Type *func_return_type = containing_func->ReturnTypeAnnotation()->GetType(checker);

        if (argument_ != nullptr) {
            checker->ElaborateElementwise(func_return_type, argument_, Start());
            return_type = checker->CheckTypeCached(argument_);
        }

        checker->IsTypeAssignableTo(return_type, func_return_type,
                                    {"Type '", return_type, "' is not assignable to type '", func_return_type, "'."},
                                    Start());
    }

    return nullptr;
}

checker::Type *ReturnStatement::Check(checker::ETSChecker *checker)
{
    ir::AstNode *ancestor = util::Helpers::FindAncestorGivenByType(this, ir::AstNodeType::SCRIPT_FUNCTION);
    ASSERT(ancestor && ancestor->IsScriptFunction());
    auto *containing_func = ancestor->AsScriptFunction();

    if (containing_func->IsConstructor()) {
        if (argument_ != nullptr) {
            checker->ThrowTypeError("Return statement with expression isn't allowed in constructor.", Start());
        }
        return nullptr;
    }

    ASSERT(containing_func->ReturnTypeAnnotation() != nullptr || containing_func->Signature()->ReturnType() != nullptr);

    checker::Type *func_return_type;

    if (auto *const return_type_annotation = containing_func->ReturnTypeAnnotation();
        return_type_annotation != nullptr) {
        // Case when function's return type is defined explicitly:
        func_return_type = checker->GetTypeFromTypeAnnotation(return_type_annotation);

        if (argument_ == nullptr) {
            if (!func_return_type->IsETSVoidType() && func_return_type != checker->GlobalBuiltinVoidType()) {
                checker->ThrowTypeError("Missing return value.", Start());
            }
            func_return_type =
                containing_func->IsEntryPoint() ? checker->GlobalVoidType() : checker->GlobalBuiltinVoidType();
        } else {
            const auto name = containing_func->Scope()->InternalName().Mutf8();
            if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
                if (func_return_type == checker->GlobalBuiltinVoidType()) {
                    func_return_type = checker->GlobalVoidType();
                } else if (!func_return_type->IsETSVoidType() && !func_return_type->IsIntType()) {
                    checker->ThrowTypeError("Bad return type, main enable only void or int type.", Start());
                }
            }

            if (argument_->IsObjectExpression()) {
                argument_->AsObjectExpression()->SetPreferredType(func_return_type);
            }
            checker::Type *argument_type = argument_->Check(checker);

            if (func_return_type->IsETSVoidType() || func_return_type == checker->GlobalBuiltinVoidType()) {
                if (argument_type != checker->GlobalVoidType() && argument_type != checker->GlobalBuiltinVoidType()) {
                    checker->ThrowTypeError("Unexpected return value, enclosing method return type is void.",
                                            argument_->Start());
                }
            } else {
                checker::AssignmentContext(
                    checker->Relation(), argument_, argument_type, func_return_type, argument_->Start(),
                    {"Return statement type is not compatible with the enclosing method's return type."},
                    checker::TypeRelationFlag::DIRECT_RETURN);
            }
        }
    } else {
        //  Case when function's return type should be inferred from return statement(s):
        if (containing_func->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
            //  First (or single) return statement in the function:
            func_return_type = argument_ == nullptr ? checker->GlobalBuiltinVoidType() : argument_->Check(checker);

            if (func_return_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
                // remove CONSTANT type modifier if exists
                func_return_type = func_return_type->Instantiate(checker->Allocator(), checker->Relation(),
                                                                 checker->GetGlobalTypesHolder());
                func_return_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
            }

            containing_func->Signature()->SetReturnType(func_return_type);
            containing_func->Signature()->RemoveSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE);

            if (argument_ != nullptr && argument_->IsObjectExpression()) {
                argument_->AsObjectExpression()->SetPreferredType(func_return_type);
            }
        } else {
            //  All subsequent return statements:
            func_return_type = containing_func->Signature()->ReturnType();

            if (argument_ == nullptr) {
                // previous return statement(s) have value
                if (!func_return_type->IsETSVoidType() && func_return_type != checker->GlobalBuiltinVoidType()) {
                    checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                            Start());
                }
            } else {
                //  previous return statement(s) don't have any value
                if (func_return_type->IsETSVoidType() || func_return_type == checker->GlobalBuiltinVoidType()) {
                    checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                            argument_->Start());
                }

                const auto name = containing_func->Scope()->InternalName().Mutf8();
                if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
                    if (func_return_type == checker->GlobalBuiltinVoidType()) {
                        func_return_type = checker->GlobalVoidType();
                    } else if (!func_return_type->IsETSVoidType() && !func_return_type->IsIntType()) {
                        checker->ThrowTypeError("Bad return type, main enable only void or int type.", Start());
                    }
                }

                if (argument_->IsObjectExpression()) {
                    argument_->AsObjectExpression()->SetPreferredType(func_return_type);
                }

                checker::Type *argument_type = argument_->Check(checker);
                // remove CONSTANT type modifier if exists
                if (argument_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
                    argument_type = argument_type->Instantiate(checker->Allocator(), checker->Relation(),
                                                               checker->GetGlobalTypesHolder());
                    argument_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
                }

                auto *const relation = checker->Relation();
                relation->SetNode(argument_);

                if (!relation->IsIdenticalTo(func_return_type, argument_type)) {
                    if (func_return_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) ||
                        argument_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                        // function return type should be of reference (object) type
                        relation->SetFlags(checker::TypeRelationFlag::NONE);

                        if (!argument_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                            argument_type = checker->PrimitiveTypeAsETSBuiltinType(argument_type);
                            if (argument_type == nullptr) {
                                checker->ThrowTypeError("Invalid return statement expression", argument_->Start());
                            }
                            // argument_->SetTsType(argument_type);
                            argument_->AddBoxingUnboxingFlag(checker->GetBoxingFlag(argument_type));
                        }

                        if (!func_return_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                            func_return_type = checker->PrimitiveTypeAsETSBuiltinType(func_return_type);
                            if (func_return_type == nullptr) {
                                checker->ThrowTypeError("Invalid return function expression", Start());
                            }
                        }

                        func_return_type = checker->FindLeastUpperBound(func_return_type, argument_type);
                        containing_func->Signature()->SetReturnType(func_return_type);
                        containing_func->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);

                    } else if (func_return_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE_RETURN) &&
                               argument_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE_RETURN)) {
                        // function return type is of primitive type (including enums):
                        relation->SetFlags(checker::TypeRelationFlag::DIRECT_RETURN |
                                           checker::TypeRelationFlag::IN_ASSIGNMENT_CONTEXT |
                                           checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);

                        if (relation->IsAssignableTo(func_return_type, argument_type)) {
                            func_return_type = argument_type;
                            // func_return_type = argument_type->Instantiate(checker->Allocator(), relation,
                            //     checker->GetGlobalTypesHolder());
                            containing_func->Signature()->SetReturnType(func_return_type);
                            containing_func->Signature()->AddSignatureFlag(
                                checker::SignatureFlags::INFERRED_RETURN_TYPE);
                        } else if (!relation->IsAssignableTo(argument_type, func_return_type)) {
                            checker->ThrowTypeError(
                                "Return statement type is not compatible with previous method's return statement "
                                "type(s).",
                                argument_->Start());
                        }

                    } else {
                        checker->ThrowTypeError("Invalid return statement type(s).", Start());
                    }
                }

                relation->SetNode(nullptr);
                relation->SetFlags(checker::TypeRelationFlag::NONE);
            }
        }
    }

    return_type_ = func_return_type;
    return nullptr;
}

void ReturnStatement::SetReturnType(checker::ETSChecker *checker, checker::Type *type)
{
    return_type_ = type;
    if (argument_ != nullptr) {
        checker::Type *argument_type = argument_->Check(checker);
        if (type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) &&
            !argument_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
            auto *const relation = checker->Relation();
            relation->SetNode(argument_);
            relation->SetFlags(checker::TypeRelationFlag::NONE);

            argument_type = checker->PrimitiveTypeAsETSBuiltinType(argument_type);
            if (argument_type == nullptr) {
                checker->ThrowTypeError("Invalid return statement expression", argument_->Start());
            }
            // argument_->SetTsType(argument_type);
            argument_->AddBoxingUnboxingFlag(checker->GetBoxingFlag(argument_type));

            relation->SetNode(nullptr);
        }
    }
}
}  // namespace panda::es2panda::ir
