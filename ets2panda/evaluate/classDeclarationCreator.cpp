/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "checker/ETSchecker.h"
#include "classDeclarationCreator.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"
#include "evaluate/helpers.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/ts/tsAsExpression.h"

#include "libpandafile/class_data_accessor-inl.h"
#include "libpandafile/debug_data_accessor-inl.h"
#include "libpandafile/include/type.h"
#include "libpandafile/method_data_accessor-inl.h"
#include "libpandafile/proto_data_accessor-inl.h"

namespace ark::es2panda::evaluate {

static std::string GetFieldName(size_t fieldIdx)
{
    std::stringstream sstream;
    sstream << "field" << fieldIdx;
    return sstream.str();
}

ClassDeclarationCreator::ClassDeclarationCreator(checker::ETSChecker *checker, NonRecursiveIrChecker &irChecker)
    : checker_(checker), irChecker_(irChecker)
{
}

ArenaAllocator *ClassDeclarationCreator::Allocator()
{
    return checker_->Allocator();
}

ir::ClassDeclaration *ClassDeclarationCreator::CreateClassDeclaration(const util::StringView &identName,
                                                                      panda_file::ClassDataAccessor &cda,
                                                                      parser::Program *program)
{
    LOG(DEBUG, ES2PANDA) << "Create class declaration from debug info: " << identName;
    auto *binder = checker_->VarBinder()->AsETSBinder();

    // Create IR for the class.
    auto *classDecl = BuildIrClass(
        identName, [this, &cda](ArenaVector<ir::AstNode *> *classBody) { CreateClassBody(classBody, cda); }, program);

    DoScopedAction(checker_, program, nullptr, nullptr, [binder, classDecl]() {
        compiler::InitScopesPhaseETS::RunExternalNode(classDecl, binder);
        binder->ResolveReferencesForScope(classDecl, compiler::NearestScope(classDecl));
    });

    // Run checker to assign types to all entities.
    irChecker_.CheckNewNode(checker_, classDecl, program->GlobalScope(), nullptr, program);

    return classDecl;
}

ir::ClassProperty *ClassDeclarationCreator::CreateClassProperty(std::string_view name, ir::TypeNode *type,
                                                                ir::ModifierFlags modifiers)
{
    ASSERT(type);

    LOG(DEBUG, ES2PANDA) << "Create class property from debug info: " << name;
    auto *fieldIdent = checker_->AllocNode<ir::Identifier>(name, Allocator());
    auto *field = checker_->AllocNode<ir::ClassProperty>(fieldIdent, nullptr, type, modifiers, Allocator(), false);

    return field;
}

ir::AstNode *ClassDeclarationCreator::CreateClassMethod(panda_file::MethodDataAccessor &mda)
{
    auto methodNameStr = mda.GetFullName();
    util::UString methodName(methodNameStr, Allocator());

    auto parameters = GetFunctionParameters(mda);
    LOG(DEBUG, ES2PANDA) << "Create method from debug info: " << methodNameStr << ", parameters #" << parameters.size();

    auto flags = ir::ModifierFlags::PUBLIC | ir::ModifierFlags::EXPORT;
    if (mda.IsStatic()) {
        flags |= ir::ModifierFlags::STATIC;
    }

    auto methodBuilder = [&](ArenaVector<ir::Statement *> *stms, ArenaVector<ir::Expression *> *params,
                             ir::TypeNode **rettype) -> void {
        *rettype = parameters[0];

        auto *retStatement = CreateTypedReturnStatement(*rettype);
        stms->push_back(retStatement);

        for (size_t idx = 1, end = parameters.size(); idx < end; ++idx) {
            util::UString paramName(GetFieldName(idx), Allocator());
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *paramIdent = checker_->AllocNode<ir::Identifier>(paramName.View(), parameters[idx], Allocator());
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *param = checker_->AllocNode<ir::ETSParameterExpression>(paramIdent, nullptr);
            params->push_back(param);
        }
    };

    bool isConstructor =
        ((methodNameStr == compiler::Signatures::CTOR) || (methodNameStr == compiler::Signatures::CCTOR));

    return CreateIrClassMethod(methodName.View(), flags, methodBuilder, isConstructor);
}

void ClassDeclarationCreator::CreateClassBody(ArenaVector<ir::AstNode *> *classBody, panda_file::ClassDataAccessor &cda)
{
    ASSERT(classBody);
    CreateFieldsProperties(classBody, cda);
    CreateFunctionProperties(classBody, cda);
}

void ClassDeclarationCreator::CreateFieldsProperties(ArenaVector<ir::AstNode *> *classBody,
                                                     panda_file::ClassDataAccessor &cda)
{
    const auto &pf = cda.GetPandaFile();

    cda.EnumerateFields([&](panda_file::FieldDataAccessor &fda) -> void {
        const char *name = utf::Mutf8AsCString(pf.GetStringData(fda.GetNameId()).data);

        auto *typeNode = PandaTypeToTypeNode(pf, fda, checker_);
        ASSERT(typeNode);

        // TODO: Ensure that everything is declared as public.
        auto *field = CreateClassProperty(name, typeNode, GetModifierFlags(fda));
        classBody->push_back(field);
    });
}

ArenaVector<ir::TypeNode *> ClassDeclarationCreator::GetFunctionParameters(panda_file::MethodDataAccessor &mda)
{
    const auto &pf = mda.GetPandaFile();
    ArenaVector<ir::TypeNode *> parameters(Allocator()->Adapter());
    mda.EnumerateTypesInProto(
        [this, &parameters, &pf = std::as_const(pf)](panda_file::Type type, panda_file::File::EntityId classId) {
            auto *typeNode = PandaTypeToTypeNode(pf, type, classId, checker_);
            ASSERT(typeNode);
            parameters.push_back(typeNode);
        },
        true);  // true -- skip `this` parameter

    return parameters;
}

ir::ReturnStatement *ClassDeclarationCreator::CreateTypedReturnStatement(ir::TypeNode *type)
{
    ASSERT(type);

    if (type->IsETSPrimitiveType() && type->AsETSPrimitiveType()->GetPrimitiveType() == ir::PrimitiveType::VOID) {
        return checker_->AllocNode<ir::ReturnStatement>();
    }

    // Hack for correct validation. This function call won't be executed in compiled code,
    // as the whole class declaration only mimics the real code loaded into runtime.

    auto *allocator = Allocator();
    auto *apiClass = checker_->AllocNode<ir::Identifier>(DEBUGGER_API_CLASS_NAME, allocator);
    auto *prop = checker_->AllocNode<ir::Identifier>(CreateGetterName(panda_file::Type::TypeId::REFERENCE), allocator);
    auto *callee = checker_->AllocNode<ir::MemberExpression>(apiClass, prop, ir::MemberExpressionKind::PROPERTY_ACCESS,
                                                             false, false);

    ArenaVector<ir::Expression *> args(1, checker_->AllocNode<ir::NumberLiteral>("0"), allocator->Adapter());
    auto *callExpression = checker_->AllocNode<ir::CallExpression>(callee, std::move(args), nullptr, false);

    auto *asExpression =
        checker_->AllocNode<ir::TSAsExpression>(callExpression, type->Clone(allocator, nullptr), false);
    return checker_->AllocNode<ir::ReturnStatement>(asExpression);
}

void ClassDeclarationCreator::CreateFunctionProperties(ArenaVector<ir::AstNode *> *classBody,
                                                       panda_file::ClassDataAccessor &cda)
{
    cda.EnumerateMethods([&classBody, this](panda_file::MethodDataAccessor &mda) -> void {
        // Parent will be set later in `BuildIrClass`
        auto *method = CreateClassMethod(mda);
        classBody->push_back(method);
    });
}

ir::AstNode *ClassDeclarationCreator::CreateIrClassMethod(util::StringView name, ir::ModifierFlags modifierFlags,
                                                          const IrMethodBuilder &builder, bool isConstructor)
{
    auto *allocator = Allocator();
    ArenaVector<ir::Expression *> params(allocator->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *id = checker_->AllocNode<ir::Identifier>(name, allocator);

    ArenaVector<ir::Statement *> statements(allocator->Adapter());
    ir::TypeNode *returnType = nullptr;

    builder(&statements, &params, &returnType);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = checker_->AllocNode<ir::BlockStatement>(allocator, std::move(statements));

    if (isConstructor) {
        return CreateIrConstructor(id, body, returnType, params, modifierFlags);
    }
    return CreateIrMethod(id, body, returnType, params, modifierFlags);
}

ir::MethodDefinition *ClassDeclarationCreator::CreateIrMethod(ir::Identifier *id, ir::BlockStatement *body,
                                                              ir::TypeNode *returnType,
                                                              ArenaVector<ir::Expression *> &params,
                                                              ir::ModifierFlags modifierFlags)
{
    auto *allocator = Allocator();
    auto funcSignature = ir::FunctionSignature(nullptr, std::move(params), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *func = checker_->AllocNode<ir::ScriptFunction>(
        allocator, ir::ScriptFunction::ScriptFunctionData {body, std::move(funcSignature),
                                                           ir::ScriptFunctionFlags::METHOD, modifierFlags});

    func->SetIdent(id);
    func->SetReturnTypeAnnotation(returnType);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = checker_->AllocNode<ir::FunctionExpression>(func);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *method = checker_->AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD,
                                                             func->Id()->Clone(allocator, nullptr), funcExpr,
                                                             modifierFlags, allocator, false);
    return method;
}

ir::AstNode *ClassDeclarationCreator::CreateIrConstructor(ir::Identifier *id, ir::BlockStatement *body,
                                                          ir::TypeNode *returnType,
                                                          ArenaVector<ir::Expression *> &params,
                                                          ir::ModifierFlags modifierFlags)
{
    auto *allocator = Allocator();

    bool isStatic = ((modifierFlags & ir::ModifierFlags::STATIC) != 0);
    auto scriptFunFlags = isStatic ? ir::ScriptFunctionFlags::STATIC_BLOCK | ir::ScriptFunctionFlags::EXPRESSION
                                   : ir::ScriptFunctionFlags::CONSTRUCTOR | ir::ScriptFunctionFlags::EXPRESSION;

    auto funcSignature = ir::FunctionSignature(nullptr, std::move(params), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *func = checker_->AllocNode<ir::ScriptFunction>(
        allocator,
        ir::ScriptFunction::ScriptFunctionData {body, std::move(funcSignature), scriptFunFlags, modifierFlags});

    func->SetIdent(id);
    func->SetReturnTypeAnnotation(returnType);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = checker_->AllocNode<ir::FunctionExpression>(func);

    if (isStatic) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *staticBlock = checker_->AllocNode<ir::ClassStaticBlock>(funcExpr, allocator);
        staticBlock->AddModifier(ir::ModifierFlags::STATIC);
        return staticBlock;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return checker_->AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR,
                                                     id->Clone(allocator, nullptr), funcExpr, ir::ModifierFlags::NONE,
                                                     allocator, false);
}

ir::ClassDeclaration *ClassDeclarationCreator::BuildIrClass(util::StringView name, const IrClassBuilder &builder,
                                                            parser::Program *program)
{
    auto *allocator = Allocator();
    ArenaVector<ir::AstNode *> classBody(allocator->Adapter());
    builder(&classBody);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *classId = checker_->AllocNode<ir::Identifier>(name, allocator);
    classId->SetReference(false);

    auto modifiers = ir::ClassDefinitionModifiers::ID_REQUIRED | ir::ClassDefinitionModifiers::CLASS_DECL |
                     ir::ClassDefinitionModifiers::DECLARATION;
    // TODO: specify super-classes, interfaces, etc.
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *classDef = checker_->AllocNode<ir::ClassDefinition>(
        util::StringView(), classId, nullptr, nullptr, ArenaVector<ir::TSClassImplements *>(allocator->Adapter()),
        nullptr, nullptr, std::move(classBody), modifiers, ir::ModifierFlags::NONE, ToLanguage(program->Extension()));

    // Set parents for all class'es fields and methods.
    for (auto *classElement : classBody) {
        classElement->SetParent(classDef);
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *classDecl = checker_->AllocNode<ir::ClassDeclaration>(classDef, allocator);
    // Declare everything as exported for correct import resolution.
    classDecl->AddModifier(ir::ModifierFlags::EXPORT);

    auto *programAst = program->Ast();
    classDecl->SetParent(programAst);
    // Here we assume that global statements of the passed `program` are not currently checked, so that
    // insertion is safe.
    programAst->Statements().push_back(classDecl);

    return classDecl;
}

}  // namespace ark::es2panda::evaluate
