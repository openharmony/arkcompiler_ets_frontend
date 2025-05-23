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

#include <algorithm>
#include "unionLowering.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"
#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"

namespace ark::es2panda::compiler {

static constexpr std::string_view PREFIX = "$NamedAccessMeta-";

static void ReplaceAll(std::string &str, std::string_view substr, std::string_view replacement)
{
    for (size_t pos = str.find(substr, 0); pos != std::string::npos; pos = str.find(substr, pos)) {
        str.replace(pos, substr.size(), replacement);
        pos += replacement.size();
    }
}

static std::string GetAccessClassName(const checker::ETSUnionType *unionType)
{
    std::stringstream ss;
    ss << PREFIX;
    unionType->ToString(ss, false);
    std::string res(ss.str());
    std::replace(res.begin(), res.end(), '.', '-');
    std::replace(res.begin(), res.end(), '|', '_');
    ReplaceAll(res, "[]", "[$]$");
    return res;
}

static ir::ClassDefinition *GetUnionAccessClass(checker::ETSChecker *checker, varbinder::VarBinder *varbinder,
                                                std::string const &name)
{
    // Create the name for the synthetic class node
    if (auto foundVar = checker->Scope()->FindLocal(util::StringView(name), varbinder::ResolveBindingOptions::BINDINGS);
        foundVar != nullptr) {
        return foundVar->Declaration()->Node()->AsClassDefinition();
    }
    util::UString unionFieldClassName(util::StringView(name), checker->Allocator());
    auto *ident = checker->AllocNode<ir::Identifier>(unionFieldClassName.View(), checker->Allocator());
    auto [decl, var] = varbinder->NewVarDecl<varbinder::ClassDecl>(ident->Start(), ident->Name());
    ident->SetVariable(var);

    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(varbinder);
    auto *classDef =
        checker->AllocNode<ir::ClassDefinition>(checker->Allocator(), ident, ir::ClassDefinitionModifiers::GLOBAL,
                                                ir::ModifierFlags::ABSTRACT, Language(Language::Id::ETS));
    classDef->SetScope(classCtx.GetScope());
    auto *classDecl = checker->AllocNode<ir::ClassDeclaration>(classDef, checker->Allocator());
    classDef->Scope()->BindNode(classDecl->Definition());
    decl->BindNode(classDef);
    var->SetScope(classDef->Scope());

    varbinder->AsETSBinder()->BuildClassDefinition(classDef);

    auto globalBlock = varbinder->Program()->Ast();
    classDecl->SetParent(globalBlock);
    globalBlock->Statements().push_back(classDecl);
    classDecl->Check(checker);
    return classDef;
}

static std::tuple<varbinder::LocalVariable *, checker::Signature *> CreateNamedAccessMethod(
    checker::ETSChecker *checker, varbinder::VarBinder *varbinder, ir::MemberExpression *expr,
    checker::Signature *signature)
{
    auto allocator = checker->Allocator();
    auto unionType = checker->GetApparentType(checker->GetNonNullishType(expr->Object()->TsType()))->AsETSUnionType();
    auto *const accessClass = GetUnionAccessClass(checker, varbinder, GetAccessClassName(unionType));
    auto methodName = expr->TsType()->AsETSFunctionType()->Name();

    // Create method name for synthetic class
    auto *methodIdent = checker->AllocNode<ir::Identifier>(methodName, allocator);

    ArenaVector<ir::Expression *> params {allocator->Adapter()};
    for (auto param : signature->Function()->Params()) {
        params.emplace_back(param->Clone(allocator, nullptr)->AsETSParameterExpression());
    }
    auto returnTypeAnno = checker->AllocNode<ir::OpaqueTypeNode>(signature->ReturnType(), allocator);

    auto *func = checker->AllocNode<ir::ScriptFunction>(
        allocator, ir::ScriptFunction::ScriptFunctionData {
                       // CC-OFFNXT(G.FMT.02-CPP) project code style
                       nullptr, ir::FunctionSignature(nullptr, std::move(params), returnTypeAnno),
                       // CC-OFFNXT(G.FMT.02-CPP) project code style
                       ir::ScriptFunctionFlags::METHOD, ir::ModifierFlags::PUBLIC});
    func->SetIdent(methodIdent->Clone(allocator, nullptr));

    // Create the synthetic function node
    auto *funcExpr = checker->AllocNode<ir::FunctionExpression>(func);

    // Create the synthetic method definition node
    auto *method = checker->AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, methodIdent, funcExpr,
                                                            ir::ModifierFlags::PUBLIC | ir::ModifierFlags::ABSTRACT,
                                                            allocator, false);
    ArenaVector<ir::AstNode *> methodDecl {allocator->Adapter()};
    methodDecl.push_back(method);
    accessClass->AddProperties(std::move(methodDecl));

    {
        auto clsCtx =
            varbinder::LexicalScope<varbinder::ClassScope>::Enter(varbinder, accessClass->Scope()->AsClassScope());
        auto boundCtx = varbinder::BoundContext(varbinder->AsETSBinder()->GetRecordTable(), accessClass, true);
        CheckLoweredNode(varbinder->AsETSBinder(), checker, method);
    }

    return {method->Id()->Variable()->AsLocalVariable(),
            method->TsType()->AsETSFunctionType()->CallSignatures().front()};
}

static varbinder::LocalVariable *CreateNamedAccessProperty(checker::ETSChecker *checker,
                                                           varbinder::VarBinder *varbinder, ir::MemberExpression *expr)
{
    auto *const allocator = checker->Allocator();
    auto unionType = checker->GetApparentType(checker->GetNonNullishType(expr->Object()->TsType()))->AsETSUnionType();
    auto *const accessClass = GetUnionAccessClass(checker, varbinder, GetAccessClassName(unionType));
    auto propName = expr->Property()->AsIdentifier()->Name();
    auto fieldType = expr->TsType();
    auto uncheckedType = expr->UncheckedType();
    auto *typeToSet = uncheckedType == nullptr ? fieldType : uncheckedType;

    // Create field name for synthetic class
    auto *fieldIdent = checker->AllocNode<ir::Identifier>(propName, allocator);

    // Create the synthetic class property node
    auto *field =
        checker->AllocNode<ir::ClassProperty>(fieldIdent, nullptr, nullptr, ir::ModifierFlags::NONE, allocator, false);

    // Add the declaration to the scope
    auto [decl, var] = varbinder->NewVarDecl<varbinder::LetDecl>(fieldIdent->Start(), fieldIdent->Name());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(typeToSet);
    fieldIdent->SetVariable(var);
    field->SetTsType(typeToSet);
    decl->BindNode(field);

    ArenaVector<ir::AstNode *> fieldDecl {allocator->Adapter()};
    fieldDecl.push_back(field);
    accessClass->AddProperties(std::move(fieldDecl));
    return var->AsLocalVariable();
}

static varbinder::LocalVariable *CreateNamedAccess(checker::ETSChecker *checker, varbinder::VarBinder *varbinder,
                                                   ir::MemberExpression *expr)
{
    auto type = expr->TsType();
    auto name = expr->Property()->AsIdentifier()->Name();

    auto unionType = checker->GetApparentType(checker->GetNonNullishType(expr->Object()->TsType()))->AsETSUnionType();
    auto *const accessClass = GetUnionAccessClass(checker, varbinder, GetAccessClassName(unionType));
    auto *classScope = accessClass->Scope()->AsClassScope();

    if (auto *var = classScope->FindLocal(name, varbinder::ResolveBindingOptions::ALL_NON_STATIC); var != nullptr) {
        return var->AsLocalVariable();
    }

    // arrow type fields should be processed as property access not method invocation
    if (type->IsETSMethodType() && !type->IsETSArrowType()) {
        auto parent = expr->Parent()->AsCallExpression();
        ES2PANDA_ASSERT(parent->Callee() == expr && parent->Signature()->HasFunction());

        auto [var, sig] = CreateNamedAccessMethod(checker, varbinder, expr, parent->Signature());
        parent->AsCallExpression()->SetSignature(sig);
        return var;
    }

    // Enter the union filed class instance field scope
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(varbinder, classScope->InstanceFieldScope());
    return CreateNamedAccessProperty(checker, varbinder, expr);
}

static void HandleUnionPropertyAccess(checker::ETSChecker *checker, varbinder::VarBinder *vbind,
                                      ir::MemberExpression *expr)
{
    if (expr->PropVar() != nullptr) {
        return;
    }

    [[maybe_unused]] auto const *const parent = expr->Parent();
    expr->SetPropVar(CreateNamedAccess(checker, vbind, expr));
    ES2PANDA_ASSERT(expr->PropVar() != nullptr);
}

static ir::TSAsExpression *GenAsExpression(checker::ETSChecker *checker, checker::Type *const opaqueType,
                                           ir::Expression *const node, ir::AstNode *const parent)
{
    auto *const typeNode = checker->AllocNode<ir::OpaqueTypeNode>(opaqueType, checker->Allocator());
    auto *const asExpression = checker->AllocNode<ir::TSAsExpression>(node, typeNode, false);
    asExpression->SetParent(parent);
    asExpression->Check(checker);
    return asExpression;
}

/*
 *  Function that generates conversion from (union) to (primitive) type as to `as` expressions:
 *      (union) as (prim) => ((union) as (ref)) as (prim),
 *      where (ref) is some unboxable type from union constituent types.
 *  Finally, `(union) as (prim)` expression replaces union_node that came above.
 */
static ir::TSAsExpression *UnionCastToPrimitive(checker::ETSChecker *checker, checker::ETSObjectType *unboxableRef,
                                                checker::Type *unboxedPrim, ir::Expression *unionNode)
{
    auto *const unionAsRefExpression = GenAsExpression(checker, unboxableRef, unionNode, nullptr);
    return GenAsExpression(checker, unboxedPrim, unionAsRefExpression, unionNode->Parent());
}

static ir::TSAsExpression *HandleUnionCastToPrimitive(checker::ETSChecker *checker, ir::TSAsExpression *expr)
{
    auto *const unionType = expr->Expr()->TsType()->AsETSUnionType();
    auto *sourceType = unionType->FindExactOrBoxedType(checker, expr->TsType());
    if (sourceType == nullptr) {
        sourceType = unionType->AsETSUnionType()->FindTypeIsCastableToSomeType(expr->Expr(), checker->Relation(),
                                                                               expr->TsType());
    }

    if (sourceType != nullptr && expr->Expr()->GetBoxingUnboxingFlags() != ir::BoxingUnboxingFlags::NONE) {
        auto *maybeUnboxingType = checker->MaybeUnboxInRelation(sourceType);
        // when sourceType get `object`, it could cast to any primitive type but can't be unboxed;
        if (maybeUnboxingType != nullptr && expr->TsType()->IsETSPrimitiveType()) {
            auto *const asExpr = GenAsExpression(checker, sourceType, expr->Expr(), expr);
            asExpr->SetBoxingUnboxingFlags(checker->GetUnboxingFlag(maybeUnboxingType));
            expr->Expr()->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::NONE);
            expr->SetExpr(asExpr);
        }

        return expr;
    }

    auto *const unboxableUnionType = sourceType != nullptr ? sourceType : unionType->FindUnboxableType();
    auto *const unboxedUnionType = checker->MaybeUnboxInRelation(unboxableUnionType);
    if (unboxableUnionType == nullptr || !unboxableUnionType->IsETSObjectType() || unboxedUnionType == nullptr) {
        return expr;
    }

    auto *const node =
        UnionCastToPrimitive(checker, unboxableUnionType->AsETSObjectType(), unboxedUnionType, expr->Expr());
    node->SetParent(expr->Parent());

    return node;
}

bool UnionLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    checker::ETSChecker *checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [checker](ir::AstNode *ast) -> ir::AstNode * {
            if (ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType() != nullptr) {
                auto *objType =
                    checker->GetApparentType(checker->GetNonNullishType(ast->AsMemberExpression()->Object()->TsType()));
                if (objType->IsETSUnionType()) {
                    HandleUnionPropertyAccess(checker, checker->VarBinder(), ast->AsMemberExpression());
                    return ast;
                }
            }
            if (ast->IsTSAsExpression() && ast->AsTSAsExpression()->Expr()->TsType() != nullptr &&
                ast->AsTSAsExpression()->Expr()->TsType()->IsETSUnionType() &&
                ast->AsTSAsExpression()->TsType() != nullptr &&
                ast->AsTSAsExpression()->TsType()->IsETSPrimitiveType()) {
                return HandleUnionCastToPrimitive(checker, ast->AsTSAsExpression());
            }

            return ast;
        },
        Name());

    return true;
}

bool UnionLowering::PostconditionForModule(public_lib::Context *ctx, const parser::Program *program)
{
    bool current = !program->Ast()->IsAnyChild([checker = ctx->checker->AsETSChecker()](ir::AstNode *ast) {
        if (!ast->IsMemberExpression() || ast->AsMemberExpression()->Object()->TsType() == nullptr) {
            return false;
        }
        auto *objType =
            checker->GetApparentType(checker->GetNonNullishType(ast->AsMemberExpression()->Object()->TsType()));
        auto *parent = ast->Parent();
        if (!parent->IsCallExpression() || parent->AsCallExpression()->Signature() == nullptr ||
            parent->AsCallExpression()->Signature()->HasFunction()) {
            return false;
        }
        return objType->IsETSUnionType() && ast->AsMemberExpression()->PropVar() == nullptr;
    });
    if (!current || ctx->config->options->GetCompilationMode() != CompilationMode::GEN_STD_LIB) {
        return current;
    }

    return true;
}

}  // namespace ark::es2panda::compiler
