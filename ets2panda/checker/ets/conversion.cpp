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

#include "conversion.h"

#include "checker/ets/boxingConverter.h"
#include "checker/ets/narrowingConverter.h"
#include "checker/ets/unboxingConverter.h"
#include "checker/ets/wideningConverter.h"

namespace panda::es2panda::checker::conversion {
void Identity(TypeRelation *const relation, Type *const source, Type *const target)
{
    relation->IsIdenticalTo(source, target);
}

void WideningPrimitive(TypeRelation *const relation, Type *const source, Type *const target)
{
    ASSERT(source->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) && target->HasTypeFlag(TypeFlag::ETS_PRIMITIVE));

    WideningConverter(relation->GetChecker()->AsETSChecker(), relation, target, source);
}

void NarrowingPrimitive(TypeRelation *const relation, Type *const source, Type *const target)
{
    ASSERT(source->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) && target->HasTypeFlag(TypeFlag::ETS_PRIMITIVE));

    NarrowingConverter(relation->GetChecker()->AsETSChecker(), relation, target, source);
}

void WideningNarrowingPrimitive(TypeRelation *const relation, ByteType *const source, CharType *const target)
{
    auto *const temp_int = relation->GetChecker()->AsETSChecker()->GetGlobalTypesHolder()->GlobalIntType();
    WideningPrimitive(relation, source, temp_int);
    if (!relation->IsTrue()) {
        return;
    }
    NarrowingPrimitive(relation, temp_int, target);
}

void WideningReference(TypeRelation *const relation, ETSObjectType *const source, ETSObjectType *const target)
{
    relation->Result(false);
    target->IsSupertypeOf(relation, source);
}

void WideningReference(TypeRelation *const relation, ETSArrayType *const source, ETSObjectType *const target)
{
    relation->Result(false);
    target->IsSupertypeOf(relation, source);
}

void WideningReference(TypeRelation *const relation, ETSArrayType *const source, ETSArrayType *const target)
{
    relation->Result(false);
    target->IsSupertypeOf(relation, source);
}

namespace {
bool IsAllowedNarrowingReferenceConversion(TypeRelation *const relation, Type *const source, Type *const target)
{
    ASSERT(source->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) &&
           target->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT));

    // 11.1.6. Narrowing Reference Conversion
    // A narrowing reference conversion exists from reference type S to a reference type T if all of the following are
    // true:

    // - S is not a subtype of T
    relation->Result(false);
    if (target->IsSupertypeOf(relation, source), relation->IsTrue()) {
        return false;
    }

    // - If there exists a parameterized type X that is a supertype of T, and a parameterized type Y that is a supertype
    //   of S, such that the erasures of X and Y are the same, then X and Y are not provably distinct
    // TODO(user): implement

    // - One of the following cases applies:

    if (source->HasTypeFlag(TypeFlag::ETS_OBJECT) && target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
        auto *const s = source->AsETSObjectType();
        auto *const t = target->AsETSObjectType();

        // 1. S and T are class types, and either |S| <: |T| or |T| <: |S|.
        // FIXME: use type erased S and T
        relation->Result(false);
        if ((t->IsSupertypeOf(relation, s), relation->IsTrue()) ||
            (s->IsSupertypeOf(relation, t), relation->IsTrue())) {
            return true;
        }

        // 2. S and T are interface types.
        if (s->HasObjectFlag(ETSObjectFlags::INTERFACE) && t->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
            return true;
        }

        // 3. S is a class type, T is an interface type, and S names class not marked as final.
        if (s->HasObjectFlag(ETSObjectFlags::CLASS) && t->HasObjectFlag(ETSObjectFlags::INTERFACE) &&
            !s->GetDeclNode()->IsFinal()) {
            return true;
        }

        // 4. S is a class type, T is an interface type, and S names a class that is marked as final and that
        //    implements the interface named by T.
        if (s->HasObjectFlag(ETSObjectFlags::CLASS) && t->HasObjectFlag(ETSObjectFlags::INTERFACE) &&
            s->GetDeclNode()->IsFinal() && (s->IsSupertypeOf(relation, t), relation->IsTrue())) {
            return true;
        }

        // 5. S is an interface type, T is a class type, and T names a class not marked as final.
        if (s->HasObjectFlag(ETSObjectFlags::INTERFACE) && t->HasObjectFlag(ETSObjectFlags::CLASS) &&
            !t->GetDeclNode()->IsFinal()) {
            return true;
        }

        // 6. S is an interface type, T is a class type, and T names a class that is marked as final and that
        //    implements the interface named by S.
        relation->Result(false);
        if (s->HasObjectFlag(ETSObjectFlags::INTERFACE) && t->HasObjectFlag(ETSObjectFlags::CLASS) &&
            t->GetDeclNode()->IsFinal() && (t->IsSupertypeOf(relation, s), relation->IsTrue())) {
            return true;
        }
    }

    if (source->HasTypeFlag(TypeFlag::ETS_OBJECT) && target->HasTypeFlag(TypeFlag::ETS_ARRAY)) {
        // 7. S is the class type Object of the interface type java.io.Serializable or Cloneable (the only interfaces
        //    implemented by arrays (link to class objects for arrays)), and T is an array type.
        // TODO(user): implement
        return true;
    }

    if (source->HasTypeFlag(TypeFlag::ETS_ARRAY) && target->HasTypeFlag(TypeFlag::ETS_ARRAY)) {
        // 8. S is an array type SC[], that is, an array of components of type SC; T is an array type TC[], that is, an
        //    array of components of type TC; and a narrowing reference conversion exists from SC to TC.
        auto *sc = source->AsETSArrayType()->ElementType();
        auto *tc = target->AsETSArrayType()->ElementType();

        if (sc->IsETSObjectType() && tc->IsETSObjectType()) {
            relation->Result(false);
            NarrowingReference(relation, sc->AsETSObjectType(), tc->AsETSObjectType());
            if (relation->IsTrue()) {
                return true;
            }
        }
    }

    // 9. S is a type variable, and a narrowing reference conversion exists from the upper bound of S to T.
    // TODO(user): implement

    // 10. T is a type variable, and either a widening reference conversion or a narrowing reference conversion exists
    //     from S to the upper bound of T.
    // TODO(user): implement

    // 11. S is an intersection type S1 & … & Sn, and for all i (1 ≤ i ≤ n), either a widening reference
    // conversion or a
    //     narrowing reference conversion exists from Si to T.
    // TODO(user): implement

    // 12. T is an intersection type T1 & … & Tn, and for all i (1 ≤ i ≤ n), either a widening reference
    // conversion or a
    //     narrowing reference conversion exists from S to Ti.
    // TODO(user): implement

    return false;
}

bool IsUncheckedNarrowingReferenceConversion([[maybe_unused]] TypeRelation *const relation,
                                             [[maybe_unused]] Type *const source, [[maybe_unused]] Type *const target)
{
    ASSERT(source->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) &&
           target->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT));

    // The unchecked narrowing reference conversions are as follows:
    // - A narrowing reference conversion from a type S to a parameterized class or interface
    //   type T is unchecked, unless at least one of the following is true:
    //   - All of the type arguments of T are unbounded wildcard.
    //   - T <: S, and S has no subtype X other than T where the type arguments of X
    //     are not contained in the type arguments of T.
    // - A narrowing reference conversion from a type S to a type variable T is unchecked.
    // - A narrowing reference conversion from a type S to an intersection type T1 & … & Tn
    //     is unchecked if there exists a Ti (1 ≤ i ≤ n) such that S is not a subtype of Ti, and a
    //     narrowing reference conversion from S to Ti is unchecked.
    // TODO(user): implement

    return false;
}

void NarrowingReferenceImpl(TypeRelation *const relation, Type *const source, Type *const target)
{
    ASSERT(target->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT));

    if (!IsAllowedNarrowingReferenceConversion(relation, source, target)) {
        Forbidden(relation);
        return;
    }

    if (!IsUncheckedNarrowingReferenceConversion(relation, source, target)) {
        relation->RemoveFlags(TypeRelationFlag::UNCHECKED_CAST);
    }

    relation->Result(true);
}
}  // namespace

void NarrowingReference(TypeRelation *const relation, ETSObjectType *const source, ETSObjectType *const target)
{
    NarrowingReferenceImpl(relation, source, target);
}

void NarrowingReference(TypeRelation *const relation, ETSArrayType *const source, ETSArrayType *const target)
{
    if (source->ElementType()->IsETSArrayType() && target->ElementType()->IsETSArrayType()) {
        NarrowingReference(relation, source->ElementType()->AsETSArrayType(), target->ElementType()->AsETSArrayType());
        return;
    }

    NarrowingReferenceImpl(relation, source, target);
}

void NarrowingReference(TypeRelation *const relation, ETSObjectType *const source, ETSArrayType *const target)
{
    if (target->ElementType()->IsETSArrayType()) {
        NarrowingReference(relation, source, target->ElementType()->AsETSArrayType());
        return;
    }

    NarrowingReferenceImpl(relation, source, target);
}

ETSObjectType *Boxing(TypeRelation *const relation, Type *const source)
{
    auto *const ets_checker = relation->GetChecker()->AsETSChecker();
    const BoxingConverter boxed(ets_checker, relation, source);
    if (!relation->IsTrue()) {
        return nullptr;
    }
    auto *const boxed_type = boxed.Result()->AsETSObjectType();
    relation->GetNode()->AddBoxingUnboxingFlag(ets_checker->GetBoxingFlag(boxed_type));
    return boxed_type;
}

Type *Unboxing(TypeRelation *const relation, ETSObjectType *const source)
{
    auto *const ets_checker = relation->GetChecker()->AsETSChecker();
    const UnboxingConverter unboxed(ets_checker, relation, source);
    if (!relation->IsTrue()) {
        return nullptr;
    }
    auto *const unboxed_type = unboxed.Result();
    relation->GetNode()->AddBoxingUnboxingFlag(ets_checker->GetUnboxingFlag(unboxed_type));
    return unboxed_type;
}

void UnboxingWideningPrimitive(TypeRelation *const relation, ETSObjectType *const source, Type *const target)
{
    auto *const unboxed_source = Unboxing(relation, source);
    if (!relation->IsTrue()) {
        return;
    }
    ASSERT(unboxed_source != nullptr);
    WideningPrimitive(relation, target, unboxed_source);
}

void NarrowingReferenceUnboxing(TypeRelation *const relation, ETSObjectType *const source, Type *const target)
{
    auto *const boxed_target = relation->GetChecker()->AsETSChecker()->PrimitiveTypeAsETSBuiltinType(target);
    if (boxed_target == nullptr) {
        return;
    }
    ASSERT(boxed_target != nullptr);
    NarrowingReference(relation, source, boxed_target->AsETSObjectType());
    if (!relation->IsTrue()) {
        return;
    }
    Unboxing(relation, boxed_target->AsETSObjectType());
}

void BoxingWideningReference(TypeRelation *const relation, Type *const source, ETSObjectType *const target)
{
    auto *const boxed_source = Boxing(relation, source);
    if (!relation->IsTrue()) {
        return;
    }
    ASSERT(boxed_source != nullptr);
    WideningReference(relation, boxed_source, target);
}

void String(TypeRelation *const relation, Type *const source)
{
    if (source->HasTypeFlag(TypeFlag::BYTE | TypeFlag::SHORT)) {
        auto *const temp_int = relation->GetChecker()->AsETSChecker()->GetGlobalTypesHolder()->GlobalIntType();
        WideningPrimitive(relation, source, temp_int);
        Boxing(relation, temp_int);
        return;
    }

    if (source->HasTypeFlag(TypeFlag::ETS_BOOLEAN | TypeFlag::CHAR | TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT |
                            TypeFlag::DOUBLE)) {
        Boxing(relation, source);
        return;
    }

    ASSERT(source->HasTypeFlag(TypeFlag::ETS_OBJECT));
}

void Forbidden(TypeRelation *const relation)
{
    relation->Result(false);
}

}  // namespace panda::es2panda::checker::conversion
