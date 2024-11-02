/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_UNION_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_UNION_TYPE_H

#include "checker/types/type.h"
#include "checker/types/ets/etsObjectType.h"

namespace ark::es2panda::checker {
class GlobalTypesHolder;

class ETSUnionType : public Type {
public:
    // constituentTypes must be normalized
    explicit ETSUnionType(ETSChecker *checker, ArenaVector<Type *> &&constituentTypes);

    [[nodiscard]] const ArenaVector<Type *> &ConstituentTypes() const noexcept
    {
        return constituentTypes_;
    }

    void ToString(std::stringstream &ss, bool precise) const override;
    void ToAssemblerType(std::stringstream &ss) const override;
    void ToDebugInfoType(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;
    Type *Substitute(TypeRelation *relation, const Substitution *substitution) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void CastTarget(TypeRelation *relation, Type *source) override;
    void IsSupertypeOf(TypeRelation *relation, Type *source) override;
    void IsSubtypeOf(TypeRelation *relation, Type *target) override;
    Type *FindTypeIsCastableToThis(ir::Expression *node, TypeRelation *relation, Type *source) const;
    Type *FindTypeIsCastableToSomeType(ir::Expression *node, TypeRelation *relation, Type *target) const;
    Type *FindUnboxableType() const;

    bool HasObjectType(ETSObjectFlags flag) const;
    bool HasUndefinedType() const;
    bool HasType(Type *type) const;
    bool HasNullishType(const ETSChecker *checker) const;

    bool IsOverlapWith(TypeRelation *relation, Type *type);

    Type *FindExactOrBoxedType(ETSChecker *checker, Type *type) const;

    static void NormalizeTypes(TypeRelation *relation, ArenaVector<Type *> &types);
    static void ReduceSubtypes(TypeRelation *relation, ArenaVector<Type *> &types);

    static ArenaVector<Type *> GetNonConstantTypes(ETSChecker *checker, const ArenaVector<Type *> &types);

    std::tuple<bool, bool> ResolveConditionExpr() const override;

    // Do not use it anywhere except codegen
    Type *GetAssemblerLUB() const
    {
        return assemblerLub_;
    }

    template <class UnaryPredicate>
    bool AllOfConstituentTypes(UnaryPredicate p) const
    {
        return std::all_of(constituentTypes_.cbegin(), constituentTypes_.cend(), p);
    }

    [[nodiscard]] checker::Type *GetAssignableType(ETSChecker *checker, checker::Type *sourceType) const noexcept;
    [[nodiscard]] std::pair<checker::Type *, checker::Type *> GetComplimentaryType(ETSChecker *checker,
                                                                                   checker::Type *sourceType);

private:
    static bool EachTypeRelatedToSomeType(TypeRelation *relation, ETSUnionType *source, ETSUnionType *target);
    static bool TypeRelatedToSomeType(TypeRelation *relation, Type *source, ETSUnionType *target);

    template <typename RelFN>
    void RelationTarget(TypeRelation *relation, Type *source, RelFN const &relFn);

    static void LinearizeAndEraseIdentical(TypeRelation *relation, ArenaVector<Type *> &types);
    [[nodiscard]] static bool ExtractType(ETSChecker *checker, checker::ETSObjectType *sourceType,
                                          ArenaVector<Type *> &unionTypes) noexcept;
    [[nodiscard]] static bool ExtractType(ETSChecker *checker, checker::ETSArrayType *sourceType,
                                          ArenaVector<Type *> &unionTypes) noexcept;

    [[nodiscard]] checker::Type *GetAssignableBuiltinType(
        checker::ETSChecker *checker, checker::ETSObjectType *sourceType, bool isBool, bool isChar,
        std::map<std::uint32_t, checker::Type *> &numericTypes) const noexcept;

    bool IsAssignableType(checker::Type *sourceType) const noexcept;

    static Type *ComputeAssemblerLUB(ETSChecker *checker, ETSUnionType *un);

    ArenaVector<Type *> const constituentTypes_;
    Type *assemblerLub_ {nullptr};
};
}  // namespace ark::es2panda::checker

#endif /* ETS_TYPES_ETS_UNION_TYPE_H */
