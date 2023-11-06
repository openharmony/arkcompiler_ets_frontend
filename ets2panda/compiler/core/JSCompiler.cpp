/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "JSCompiler.h"

#include "compiler/base/lreference.h"
#include "compiler/core/pandagen.h"
#include "ir/base/catchClause.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/returnStatement.h"
#include "util/helpers.h"

namespace panda::es2panda::compiler {

PandaGen *JSCompiler::GetPandaGen() const
{
    return static_cast<PandaGen *>(GetCodeGen());
}

// from as folder
void JSCompiler::Compile([[maybe_unused]] const ir::NamedType *node) const
{
    UNREACHABLE();
}

void JSCompiler::Compile([[maybe_unused]] const ir::PrefixAssertionExpression *expr) const
{
    UNREACHABLE();
}

// from base folder
void JSCompiler::Compile(const ir::CatchClause *st) const
{
    PandaGen *pg = GetPandaGen();
    compiler::LocalRegScope lrs(pg, st->Scope()->ParamScope());

    if (st->Param() != nullptr) {
        auto lref = compiler::JSLReference::Create(pg, st->Param(), true);
        lref.SetValue();
    }

    ASSERT(st->Scope() == st->Body()->Scope());
    st->Body()->Compile(pg);
}

static compiler::VReg CompileHeritageClause(compiler::PandaGen *pg, const ir::ClassDefinition *node)
{
    compiler::VReg base_reg = pg->AllocReg();

    if (node->Super() != nullptr) {
        node->Super()->Compile(pg);
    } else {
        pg->LoadConst(node, compiler::Constant::JS_HOLE);
    }

    pg->StoreAccumulator(node, base_reg);
    return base_reg;
}

// NOLINTNEXTLINE(google-runtime-references)
static std::tuple<int32_t, compiler::LiteralBuffer> CreateClassStaticProperties(
    compiler::PandaGen *pg, util::BitSet &compiled, const ArenaVector<ir::AstNode *> &properties)
{
    compiler::LiteralBuffer buf {};
    compiler::LiteralBuffer private_buf {};
    compiler::LiteralBuffer static_buf {};
    bool seen_computed = false;
    std::unordered_map<util::StringView, size_t> prop_name_map;
    std::unordered_map<util::StringView, size_t> static_prop_name_map;

    for (size_t i = 0; i < properties.size(); i++) {
        const ir::ClassElement *prop = properties[i]->AsClassElement();

        if (prop->IsClassStaticBlock()) {
            continue;
        }

        if (prop->IsClassProperty()) {
            bool is_static = prop->IsStatic();
            if (prop->IsPrivateElement()) {
                private_buf.emplace_back(static_cast<uint32_t>(prop->ToPrivateFieldKind(is_static)));
                private_buf.emplace_back(prop->Id()->Name());
                continue;
            }
            continue;
        }

        ASSERT(prop->IsMethodDefinition());
        const ir::MethodDefinition *prop_method = prop->AsMethodDefinition();

        if (!util::Helpers::IsConstantPropertyKey(prop_method->Key(), prop_method->IsComputed()) ||
            (prop_method->IsComputed() && util::Helpers::IsSpecialPropertyKey(prop_method->Key()))) {
            seen_computed = true;
            continue;
        }

        util::StringView name = util::Helpers::LiteralToPropName(prop->Key());
        compiler::LiteralBuffer &literal_buf = prop->IsStatic() ? static_buf : buf;
        auto &name_map = prop->IsStatic() ? static_prop_name_map : prop_name_map;

        if (prop->IsPrivateElement()) {
            private_buf.emplace_back(static_cast<uint32_t>(prop->ToPrivateFieldKind(prop_method->IsStatic())));
            private_buf.emplace_back(name);

            const ir::ScriptFunction *func = prop_method->Value()->AsFunctionExpression()->Function();

            compiler::LiteralTag tag = compiler::LiteralTag::METHOD;
            if (func->IsAsyncFunc()) {
                if (func->IsGenerator()) {
                    tag = compiler::LiteralTag::ASYNC_GENERATOR_METHOD;
                } else {
                    tag = compiler::LiteralTag::ASYNC_METHOD;
                }
            } else if (func->IsGenerator()) {
                tag = compiler::LiteralTag::GENERATOR_METHOD;
            }

            private_buf.emplace_back(tag, func->Scope()->InternalName());
            compiled.Set(i);
            continue;
        }

        size_t buffer_pos = literal_buf.size();
        auto res = name_map.insert({name, buffer_pos});
        if (res.second) {
            if (seen_computed) {
                break;
            }

            literal_buf.emplace_back(name);
            literal_buf.emplace_back();
        } else {
            buffer_pos = res.first->second;
        }

        compiler::Literal value {};

        switch (prop_method->Kind()) {
            case ir::MethodDefinitionKind::METHOD: {
                const ir::FunctionExpression *func = prop_method->Value()->AsFunctionExpression();
                const util::StringView &internal_name = func->Function()->Scope()->InternalName();

                value = compiler::Literal(compiler::LiteralTag::METHOD, internal_name);
                compiled.Set(i);
                break;
            }
            case ir::MethodDefinitionKind::GET:
            case ir::MethodDefinitionKind::SET: {
                value = compiler::Literal::NullLiteral();
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        literal_buf[buffer_pos + 1] = std::move(value);
    }

    uint32_t lit_pairs = buf.size() / 2;

    /* Static items are stored at the end of the buffer */
    buf.insert(buf.end(), static_buf.begin(), static_buf.end());

    /* The last literal item represents the offset of the first static property. The regular property literal count
     * is divided by 2 as key/value pairs count as one. */
    buf.emplace_back(lit_pairs);

    return {pg->AddLiteralBuffer(std::move(buf)), private_buf};
}

static void CompileStaticFieldInitializers(compiler::PandaGen *pg, compiler::VReg class_reg,
                                           const std::vector<compiler::VReg> &static_computed_field_keys,
                                           const ir::ClassDefinition *node)
{
    const auto &properties = node->Body();
    auto iter = static_computed_field_keys.begin();

    if (node->HasPrivateMethod()) {
        pg->ClassPrivateMethodOrAccessorAdd(node, class_reg, class_reg);
    }

    for (const auto *it : properties) {
        compiler::RegScope rs(pg);

        if (it->IsClassStaticBlock()) {
            const auto *func = it->AsClassStaticBlock()->Value()->AsFunctionExpression()->Function();

            compiler::VReg func_reg = pg->AllocReg();
            compiler::VReg this_reg = pg->AllocReg();

            pg->LoadAccumulator(it, class_reg);
            pg->StoreAccumulator(it, this_reg);
            pg->DefineMethod(it, func->Scope()->InternalName());
            pg->StoreAccumulator(it, func_reg);

            pg->Call0This(node, func_reg, this_reg);
            continue;
        }

        if (it->IsMethodDefinition()) {
            continue;
        }

        ASSERT(it->IsClassProperty());
        const ir::ClassProperty *prop = it->AsClassProperty();

        if (!prop->IsStatic()) {
            continue;
        }

        compiler::VReg key_reg {};

        if (prop->IsComputed()) {
            ASSERT(iter != static_computed_field_keys.end());
            key_reg = *iter++;
        } else if (!prop->IsPrivateElement()) {
            key_reg = pg->LoadPropertyKey(prop->Key(), false);
        }

        if (prop->Value() == nullptr) {
            pg->LoadConst(prop, compiler::Constant::JS_UNDEFINED);
        } else {
            compiler::RegScope vrs(pg);
            prop->Value()->Compile(pg);
        }

        if (prop->IsPrivateElement()) {
            pg->ClassPrivateFieldAdd(prop, class_reg, class_reg, prop->Id()->Name());
            continue;
        }

        pg->ClassFieldAdd(prop, class_reg, key_reg);
    }
}

static void CompileMissingProperties(compiler::PandaGen *pg, const util::BitSet &compiled, compiler::VReg class_reg,
                                     const ir::ClassDefinition *node)
{
    const auto &properties = node->Body();
    std::vector<compiler::VReg> static_computed_field_keys;
    compiler::VReg proto_reg = pg->AllocReg();
    compiler::VReg computed_instance_fields_array {};
    uint32_t computed_instance_fields_index = 0;

    pg->LoadObjByName(node, "prototype");
    pg->StoreAccumulator(node, proto_reg);

    if (node->HasComputedInstanceField()) {
        pg->CreateEmptyArray(node);
        computed_instance_fields_array = pg->AllocReg();
        pg->StoreAccumulator(node, computed_instance_fields_array);
    }

    for (size_t i = 0; i < properties.size(); i++) {
        if (compiled.Test(i)) {
            continue;
        }

        if (properties[i]->IsClassStaticBlock()) {
            continue;
        }

        if (properties[i]->IsMethodDefinition()) {
            const ir::MethodDefinition *prop = properties[i]->AsMethodDefinition();
            compiler::VReg dest = prop->IsStatic() ? class_reg : proto_reg;
            compiler::RegScope rs(pg);

            switch (prop->Kind()) {
                case ir::MethodDefinitionKind::METHOD: {
                    compiler::Operand key = pg->ToOwnPropertyKey(prop->Key(), prop->IsComputed());

                    pg->LoadAccumulator(node, dest);
                    const ir::FunctionExpression *func = prop->Value()->AsFunctionExpression();
                    func->Compile(pg);

                    pg->StoreOwnProperty(prop->Value()->Parent(), dest, key);
                    break;
                }
                case ir::MethodDefinitionKind::GET:
                case ir::MethodDefinitionKind::SET: {
                    compiler::VReg key_reg = pg->LoadPropertyKey(prop->Key(), prop->IsComputed());

                    compiler::VReg undef = pg->AllocReg();
                    pg->LoadConst(node, compiler::Constant::JS_UNDEFINED);
                    pg->StoreAccumulator(node, undef);

                    compiler::VReg getter = undef;
                    compiler::VReg setter = undef;

                    pg->LoadAccumulator(node, dest);

                    compiler::VReg accessor = pg->AllocReg();
                    prop->Value()->Compile(pg);
                    pg->StoreAccumulator(prop->Value(), accessor);

                    if (prop->Kind() == ir::MethodDefinitionKind::GET) {
                        getter = accessor;
                    } else {
                        setter = accessor;
                    }

                    pg->DefineGetterSetterByValue(node, dest, key_reg, getter, setter, prop->IsComputed());
                    break;
                }
                default: {
                    UNREACHABLE();
                }
            }

            continue;
        }

        ASSERT(properties[i]->IsClassProperty());
        const ir::ClassProperty *prop = properties[i]->AsClassProperty();

        if (!prop->IsComputed()) {
            continue;
        }

        if (prop->IsStatic()) {
            compiler::VReg key_reg = pg->LoadPropertyKey(prop->Key(), prop->IsComputed());
            static_computed_field_keys.push_back(key_reg);
            continue;
        }

        pg->LoadPropertyKeyAcc(prop->Key(), prop->IsComputed());
        pg->StOwnByIndex(node, computed_instance_fields_array, computed_instance_fields_index++);
    }

    if (computed_instance_fields_index != 0) {
        pg->SetClassComputedFields(node, class_reg, computed_instance_fields_array);
    }

    CompileStaticFieldInitializers(pg, class_reg, static_computed_field_keys, node);
}

static void InitializeClassName(compiler::PandaGen *pg, const ir::ClassDefinition *node)
{
    if (node->Ident() == nullptr) {
        return;
    }

    auto lref = compiler::JSLReference::Create(pg, node->Ident(), true);
    lref.SetValue();
}

void JSCompiler::Compile(const ir::ClassDefinition *node) const
{
    PandaGen *pg = GetPandaGen();
    compiler::RegScope rs(pg);
    compiler::VReg class_reg = pg->AllocReg();
    compiler::VReg lexenv = pg->LexEnv();

    compiler::LocalRegScope lrs(pg, node->Scope());

    compiler::VReg base_reg = CompileHeritageClause(pg, node);
    util::StringView ctor_id = node->Ctor()->Function()->Scope()->InternalName();
    util::BitSet compiled(node->Body().size());

    auto [bufIdx, privateBuf] = CreateClassStaticProperties(pg, compiled, node->Body());

    pg->DefineClassWithBuffer(node, ctor_id, bufIdx, lexenv, base_reg);
    pg->StoreAccumulator(node, class_reg);

    if (!privateBuf.empty()) {
        pg->DefineClassPrivateFields(node, pg->AddLiteralBuffer(std::move(privateBuf)));
    }

    auto res = pg->Scope()->Find(node->PrivateId());
    ASSERT(res.variable);

    if (res.variable->AsLocalVariable()->LexicalBound()) {
        pg->StoreLexicalVar(node, res.lex_level, res.variable->AsLocalVariable()->LexIdx());
    }

    InitializeClassName(pg, node);

    CompileMissingProperties(pg, compiled, class_reg, node);

    pg->LoadAccumulator(node, class_reg);
}

void JSCompiler::Compile([[maybe_unused]] const ir::ClassProperty *st) const
{
    UNREACHABLE();
}

void JSCompiler::Compile([[maybe_unused]] const ir::ClassStaticBlock *st) const
{
    UNREACHABLE();
}

void JSCompiler::Compile([[maybe_unused]] const ir::Decorator *st) const
{
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::MetaProperty *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::MethodDefinition *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::Property *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ScriptFunction *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::SpreadElement *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TemplateElement *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSIndexSignature *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSMethodSignature *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSPropertySignature *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSSignatureDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}
// from ets folder
void JSCompiler::Compile(const ir::ETSClassLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSFunctionType *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSImportDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSLaunchExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSNewArrayInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSNewClassInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSPackageDeclaration *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSParameterExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSPrimitiveType *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSStructDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSTypeReference *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSTypeReferencePart *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ETSWildcardType *expr) const
{
    (void)expr;
    UNREACHABLE();
}

// JSCompiler::compile methods for EXPRESSIONS in alphabetical order
void JSCompiler::Compile(const ir::ArrayExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ArrowFunctionExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::AssignmentExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::AwaitExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::BinaryExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::CallExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ChainExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ClassExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ConditionalExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::DirectEvalExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::FunctionExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::Identifier *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ImportExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::MemberExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::NewExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ObjectExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::OpaqueTypeNode *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::OmittedExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::SequenceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::SuperExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TaggedTemplateExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TemplateLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ThisExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::UnaryExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::UpdateExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::YieldExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}
// Compile methods for LITERAL EXPRESSIONS in alphabetical order
void JSCompiler::Compile(const ir::BigIntLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::BooleanLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::CharLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::NullLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::NumberLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::RegExpLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::StringLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}
// Compile methods for MODULE-related nodes in alphabetical order
void JSCompiler::Compile(const ir::ExportAllDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ExportDefaultDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ExportNamedDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ExportSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ImportDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ImportDefaultSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ImportNamespaceSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ImportSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}
// Compile methods for STATEMENTS in alphabetical order
void JSCompiler::Compile(const ir::AssertStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::BlockStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::BreakStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ClassDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ContinueStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::DebuggerStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::DoWhileStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::EmptyStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ExpressionStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ForInStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ForOfStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ForUpdateStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::FunctionDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::IfStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::LabelledStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ReturnStatement *st) const
{
    PandaGen *pg = GetPandaGen();
    if (st->Argument() != nullptr) {
        st->Argument()->Compile(pg);
    } else {
        pg->LoadConst(st, compiler::Constant::JS_UNDEFINED);
    }

    if (pg->CheckControlFlowChange()) {
        compiler::RegScope rs(pg);
        compiler::VReg res = pg->AllocReg();

        pg->StoreAccumulator(st, res);
        pg->ControlFlowChangeBreak();
        pg->LoadAccumulator(st, res);
    }

    if (st->Argument() != nullptr) {
        pg->ValidateClassDirectReturn(st);
        pg->DirectReturn(st);
    } else {
        pg->ImplicitReturn(st);
    }
}

void JSCompiler::Compile(const ir::SwitchCaseStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::SwitchStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::ThrowStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TryStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::VariableDeclarator *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::VariableDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::WhileStatement *st) const
{
    (void)st;
    UNREACHABLE();
}
// from ts folder
void JSCompiler::Compile(const ir::TSAnyKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSArrayType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSAsExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSBigintKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSBooleanKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSClassImplements *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSConditionalType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSConstructorType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSEnumDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSEnumMember *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSExternalModuleReference *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSFunctionType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSImportEqualsDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSImportType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSIndexedAccessType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSInferType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSInterfaceBody *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSInterfaceDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSInterfaceHeritage *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSIntersectionType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSLiteralType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSMappedType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSModuleBlock *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSModuleDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSNamedTupleMember *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSNeverKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSNonNullExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSNullKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSNumberKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSObjectKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSParameterProperty *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSParenthesizedType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSQualifiedName *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSStringKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSThisType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTupleType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeAliasDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeAssertion *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeLiteral *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeOperator *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeParameter *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeParameterDeclaration *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeParameterInstantiation *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypePredicate *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeQuery *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSTypeReference *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSUndefinedKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSUnionType *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSUnknownKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void JSCompiler::Compile(const ir::TSVoidKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

}  // namespace panda::es2panda::compiler