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

#include "classDefinition.h"

#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/compiler/base/literals.h"
#include "plugins/ecmascript/es2panda/compiler/base/lreference.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/base/classProperty.h"
#include "plugins/ecmascript/es2panda/ir/base/methodDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/base/classStaticBlock.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/functionExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/nullLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/numberLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsClassImplements.h"
#include "plugins/ecmascript/es2panda/ir/base/tsIndexSignature.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameter.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameterDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameterInstantiation.h"

namespace panda::es2panda::ir {
const FunctionExpression *ClassDefinition::Ctor() const
{
    return ctor_ != nullptr ? ctor_->Value()->AsFunctionExpression() : nullptr;
}

bool ClassDefinition::HasPrivateMethod() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsMethodDefinition() && element->AsClassElement()->IsPrivateElement();
    });
}

bool ClassDefinition::HasComputedInstanceField() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsClassProperty() && element->AsClassElement()->IsComputed() &&
               !(element->AsClassElement()->Modifiers() & ir::ModifierFlags::STATIC);
    });
}

bool ClassDefinition::HasMatchingPrivateKey(const util::StringView &name) const
{
    return std::any_of(body_.cbegin(), body_.cend(), [&name](auto *element) {
        return element->AsClassElement()->IsPrivateElement() && element->AsClassElement()->Id()->Name() == name;
    });
}

void ClassDefinition::Iterate(const NodeTraverser &cb) const
{
    if (ident_ != nullptr) {
        cb(ident_);
    }

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    if (super_class_ != nullptr) {
        cb(super_class_);
    }

    if (super_type_params_ != nullptr) {
        cb(super_type_params_);
    }

    for (auto *it : implements_) {
        cb(it);
    }

    if (ctor_ != nullptr) {
        cb(ctor_);
    }

    for (auto *it : body_) {
        cb(it);
    }
}

void ClassDefinition::Dump(ir::AstDumper *dumper) const
{
    auto prop_filter = [](AstNode *prop) -> bool {
        return !prop->IsClassStaticBlock() || !prop->AsClassStaticBlock()->Function()->IsHidden();
    };
    dumper->Add({{"id", AstDumper::Nullable(ident_)},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"superClass", AstDumper::Nullable(super_class_)},
                 {"superTypeParameters", AstDumper::Optional(super_type_params_)},
                 {"implements", implements_},
                 {"constructor", AstDumper::Optional(ctor_)},
                 {"body", body_, prop_filter}});
}

compiler::VReg ClassDefinition::CompileHeritageClause(compiler::PandaGen *pg) const
{
    compiler::VReg base_reg = pg->AllocReg();

    if (super_class_ != nullptr) {
        super_class_->Compile(pg);
    } else {
        pg->LoadConst(this, compiler::Constant::JS_HOLE);
    }

    pg->StoreAccumulator(this, base_reg);
    return base_reg;
}

void ClassDefinition::InitializeClassName(compiler::PandaGen *pg) const
{
    if (ident_ == nullptr) {
        return;
    }

    auto lref = compiler::JSLReference::Create(pg, ident_, true);
    lref.SetValue();
}

// NOLINTNEXTLINE(google-runtime-references)
static std::tuple<int32_t, compiler::LiteralBuffer> CreateClassStaticProperties(
    compiler::PandaGen *pg, util::BitSet &compiled, const ArenaVector<AstNode *> &properties)
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

void ClassDefinition::CompileMissingProperties(compiler::PandaGen *pg, const util::BitSet &compiled,
                                               compiler::VReg class_reg) const
{
    const auto &properties = body_;
    std::vector<compiler::VReg> static_computed_field_keys;
    compiler::VReg proto_reg = pg->AllocReg();
    compiler::VReg computed_instance_fields_array {};
    uint32_t computed_instance_fields_index = 0;

    pg->LoadObjByName(this, "prototype");
    pg->StoreAccumulator(this, proto_reg);

    if (HasComputedInstanceField()) {
        pg->CreateEmptyArray(this);
        computed_instance_fields_array = pg->AllocReg();
        pg->StoreAccumulator(this, computed_instance_fields_array);
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

                    pg->LoadAccumulator(this, dest);
                    const ir::FunctionExpression *func = prop->Value()->AsFunctionExpression();
                    func->Compile(pg);

                    pg->StoreOwnProperty(prop->Value()->Parent(), dest, key);
                    break;
                }
                case ir::MethodDefinitionKind::GET:
                case ir::MethodDefinitionKind::SET: {
                    compiler::VReg key_reg = pg->LoadPropertyKey(prop->Key(), prop->IsComputed());

                    compiler::VReg undef = pg->AllocReg();
                    pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
                    pg->StoreAccumulator(this, undef);

                    compiler::VReg getter = undef;
                    compiler::VReg setter = undef;

                    pg->LoadAccumulator(this, dest);

                    compiler::VReg accessor = pg->AllocReg();
                    prop->Value()->Compile(pg);
                    pg->StoreAccumulator(prop->Value(), accessor);

                    if (prop->Kind() == ir::MethodDefinitionKind::GET) {
                        getter = accessor;
                    } else {
                        setter = accessor;
                    }

                    pg->DefineGetterSetterByValue(this, dest, key_reg, getter, setter, prop->IsComputed());
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
        pg->StOwnByIndex(this, computed_instance_fields_array, computed_instance_fields_index++);
    }

    if (computed_instance_fields_index != 0) {
        pg->SetClassComputedFields(this, class_reg, computed_instance_fields_array);
    }

    CompileStaticFieldInitializers(pg, class_reg, static_computed_field_keys);
}

void ClassDefinition::CompileStaticFieldInitializers(
    compiler::PandaGen *pg, compiler::VReg class_reg,
    const std::vector<compiler::VReg> &static_computed_field_keys) const
{
    const auto &properties = body_;
    auto iter = static_computed_field_keys.begin();

    if (HasPrivateMethod()) {
        pg->ClassPrivateMethodOrAccessorAdd(this, class_reg, class_reg);
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

            pg->Call0This(this, func_reg, this_reg);
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

void ClassDefinition::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    compiler::VReg class_reg = pg->AllocReg();
    compiler::VReg lexenv = pg->LexEnv();

    compiler::LocalRegScope lrs(pg, scope_);

    compiler::VReg base_reg = CompileHeritageClause(pg);
    util::StringView ctor_id = ctor_->Function()->Scope()->InternalName();
    util::BitSet compiled(body_.size());

    auto [bufIdx, privateBuf] = CreateClassStaticProperties(pg, compiled, body_);

    pg->DefineClassWithBuffer(this, ctor_id, bufIdx, lexenv, base_reg);
    pg->StoreAccumulator(this, class_reg);

    if (!privateBuf.empty()) {
        pg->DefineClassPrivateFields(this, pg->AddLiteralBuffer(std::move(privateBuf)));
    }

    auto res = pg->Scope()->Find(private_id_);
    ASSERT(res.variable);

    if (res.variable->AsLocalVariable()->LexicalBound()) {
        pg->StoreLexicalVar(this, res.lex_level, res.variable->AsLocalVariable()->LexIdx());
    }

    InitializeClassName(pg);

    CompileMissingProperties(pg, compiled, class_reg);

    pg->LoadAccumulator(this, class_reg);
}

checker::Type *ClassDefinition::Check([[maybe_unused]] checker::TSChecker *checker)
{
    // TODO(aszilagyi)
    return checker->GlobalAnyType();
}

checker::Type *ClassDefinition::Check(checker::ETSChecker *checker)
{
    if (TsType() == nullptr) {
        checker->BuildClassProperties(this);
    }

    checker->CheckClassDefinition(this);
    return nullptr;
}
}  // namespace panda::es2panda::ir
