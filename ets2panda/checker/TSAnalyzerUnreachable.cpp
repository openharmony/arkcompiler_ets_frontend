/*
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

#include "TSAnalyzer.h"

namespace ark::es2panda::checker {

// from as folder
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::NamedType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::PrefixAssertionExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassProperty *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassStaticBlock *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::Decorator *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::MethodDefinition *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::Property *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ScriptFunction *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::SpreadElement *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TemplateElement *expr) const
{
    UNREACHABLE();
}

// from ets folder
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSScript *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSClassLiteral *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSFunctionType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSImportDeclaration *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSLaunchExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSNewArrayInstanceExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSNewClassInstanceExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSPackageDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSParameterExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSPrimitiveType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSStructDeclaration *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSTuple *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSTypeReference *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSTypeReferencePart *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSNullType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSUndefinedType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSNeverType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSStringLiteralType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSUnionType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSWildcardType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::BlockExpression *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::DirectEvalExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::CharLiteral *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::UndefinedLiteral *expr) const
{
    UNREACHABLE();
}

// compile methods for MODULE-related nodes in alphabetical order
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ExportAllDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ExportDefaultDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ExportNamedDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ExportSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportDefaultSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportNamespaceSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportSpecifier *st) const
{
    UNREACHABLE();
}
// compile methods for STATEMENTS in alphabetical order
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::AssertStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ContinueStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::DebuggerStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ForInStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ForOfStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::LabelledStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::SwitchCaseStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ThrowStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSClassImplements *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSConditionalType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSReExportDeclaration *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSEnumMember *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSExternalModuleReference *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSImportEqualsDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSImportType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSInferType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSInterfaceHeritage *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSIntersectionType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSMappedType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSModuleBlock *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSModuleDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSNonNullExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSObjectKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSParameterProperty *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSThisType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeAssertion *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeOperator *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameter *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameterDeclaration *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameterInstantiation *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypePredicate *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::DummyNode *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::NamespaceDeclaration *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::NamespaceDefinition *expr) const
{
    UNREACHABLE();
}
}  // namespace ark::es2panda::checker
