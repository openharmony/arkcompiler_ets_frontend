/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

import * as NodeBuilder from "../transpiler/NodeBuilder";
import * as sts from "../../build/typescript/StaticTSParser";

// TODO: These are just the functions needed to emit aliasing function declaration.
// This should be continued to cover all of arkTS AST node types.

export function cloneSignature(stsSignature: sts.SignatureContext): sts.SignatureContext {
    let stsSignatureClone = new sts.SignatureContext(undefined, 0);

    // Clone type parameters, if any.
    let stsTypeParams = stsSignature.typeParameters();
    if (stsTypeParams) stsSignatureClone.addChild(cloneTypeParameters(stsTypeParams));

    // Clone function parameters, if any.
    let stsParamList = stsSignature.parameterList();
    if (stsParamList) stsSignatureClone.addChild(cloneParameterList(stsParamList));

    // Clone return type.
    let stsTypeAnno = stsSignature.typeAnnotation();
    stsSignatureClone.addChild(cloneTypeAnnotation(stsTypeAnno));

    // Clone throws/rethrows keyword, if exists.
    let stsThrowsAnno = stsSignature.throwsAnnotation();
    if (stsThrowsAnno) stsSignatureClone.addChild(cloneThrowsAnnotation(stsThrowsAnno));

    return stsSignatureClone;
}

export function cloneThrowsAnnotation(stsThrowsAnno: sts.ThrowsAnnotationContext): sts.ThrowsAnnotationContext {
    let stsThrowsAnnoClone = new sts.ThrowsAnnotationContext(undefined, 0);
    stsThrowsAnnoClone.addChild(NodeBuilder.terminalIdentifier(stsThrowsAnno.Identifier().text));

    return stsThrowsAnnoClone;
}

export function cloneTypeParameters(stsTypeParams: sts.TypeParametersContext): sts.TypeParametersContext {
    let stsTypeParamsClone = new sts.TypeParametersContext(undefined, 0);

    // Create type parameter list.
    let stsTypeParamListClone = new sts.TypeParameterListContext(stsTypeParamsClone, 0);
    stsTypeParamsClone.addChild(stsTypeParamListClone);

    // Clone type parameters.
    for (let stsTypeParam of stsTypeParams.typeParameterList().typeParameter()) {
        let stsTypeParamClone = new sts.TypeParameterContext(stsTypeParamListClone, 0);

        // Clone in/out keyword (if exists) and type parameter name.
        for (let stsIdentifier of stsTypeParam.Identifier()) {
            stsTypeParamClone.addChild(NodeBuilder.terminalIdentifier(stsIdentifier.text));
        }
        
        // Clone constraint, if exists.
        let stsConstraint = stsTypeParam.constraint();
        if (stsConstraint) {
            let stsConstraintClone = new sts.ConstraintContext(stsTypeParamClone, 0);

            // Clone extends keyword.
            let stsIdentifier = stsConstraint.Identifier();
            stsConstraintClone.addChild(NodeBuilder.terminalIdentifier(stsIdentifier.text));

            // Clone type reference or intersection type.
            let stsTypeRef = stsConstraint.typeReference();
            if (stsTypeRef) {
                stsConstraintClone.addChild(cloneTypeReference(stsTypeRef));
            }
            else {
                let stsIntersectionType = stsConstraint.intersectionType();
                stsConstraintClone.addChild(cloneIntersectionType(stsIntersectionType));
            }

            stsTypeParamClone.addChild(stsConstraintClone);
        }

        stsTypeParamListClone.addChild(stsTypeParamClone);
    }

    return stsTypeParamsClone;
}

export function cloneParameterList(stsParamList: sts.ParameterListContext): sts.ParameterListContext {
    let stsParamListClone = new sts.ParameterListContext(undefined, 0);

    // Clone regular parameters, if any.
    let stsParams = stsParamList.parameter();
    if (stsParams) {
        for (let stsParam of stsParams) {
            let stsParamClone = new sts.ParameterContext(stsParamListClone, 0);

            let stsIdentifier = stsParam.Identifier();
            stsParamClone.addChild(NodeBuilder.terminalIdentifier(stsIdentifier.text));

            let stsTypeAnno = stsParam.typeAnnotation();
            stsParamClone.addChild(cloneTypeAnnotation(stsTypeAnno));

            stsParamListClone.addChild(stsParamClone);
        }
    }

    // Clone variadic parameter, if exists.
    let stsVarParam = stsParamList.variadicParameter();
    if (stsVarParam) {
        let stsVarParamClone = new sts.VariadicParameterContext(stsParamListClone, 0);
        stsVarParamClone.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Ellipsis));

        let stsIdentifier = stsVarParam.Identifier();
        stsVarParamClone.addChild(NodeBuilder.terminalIdentifier(stsIdentifier.text));

        let stsTypeAnno = stsVarParam.typeAnnotation();
        stsVarParamClone.addChild(cloneTypeAnnotation(stsTypeAnno));

        stsParamListClone.addChild(stsVarParamClone);
    }

    return stsParamListClone;
}

export function cloneTypeAnnotation(stsTypeAnno: sts.TypeAnnotationContext): sts.TypeAnnotationContext {
    let stsTypeAnnoClone = new sts.TypeAnnotationContext(undefined, 0);
    
    let stsPrimaryType = stsTypeAnno.primaryType();
    stsTypeAnnoClone.addChild(clonePrimaryType(stsPrimaryType));

    return stsTypeAnnoClone;
}

export function clonePrimaryType(stsPrimaryType: sts.PrimaryTypeContext): sts.PrimaryTypeContext {
    let stsPrimaryTypeClone = new sts.PrimaryTypeContext(undefined, 0);

    // Clone predefined type, if exists.
    let stsPredefinedType = stsPrimaryType.predefinedType();
    if (stsPredefinedType) {
        stsPrimaryTypeClone.addChild(clonePredefinedType(stsPredefinedType));
        return stsPrimaryTypeClone;
    }

    // Clone type reference, if exists.
    let stsTypeRef = stsPrimaryType.typeReference();
    if (stsTypeRef) {
        stsPrimaryTypeClone.addChild(cloneTypeReference(stsTypeRef));
        return stsPrimaryTypeClone;
    }

    // Clone array type, if exists.
    let stsArrayType = stsPrimaryType.arrayType();
    if (stsArrayType) {
        stsPrimaryTypeClone.addChild(cloneArrayType(stsArrayType));
        return stsPrimaryTypeClone;
    }

    // Clone function type, if exists.
    let stsFunctionType = stsPrimaryType.functionType();
    if (stsFunctionType) {
        stsPrimaryTypeClone.addChild(cloneFunctionType(stsFunctionType));
        return stsPrimaryTypeClone;
    }

    // Clone nullable type.
    let stsNullableType = stsPrimaryType.nullableType();
    stsPrimaryTypeClone.addChild(cloneNullableType(stsNullableType));
    return stsPrimaryTypeClone;
}

export function clonePredefinedType(stsPredefinedType: sts.PredefinedTypeContext): sts.PredefinedTypeContext {
    let stsPredefinedTypeClone = new sts.PredefinedTypeContext(undefined, 0);

    let stsIdentifier = stsPredefinedType.Identifier();
    stsPredefinedTypeClone.addChild(NodeBuilder.terminalIdentifier(stsIdentifier.text));

    return stsPredefinedTypeClone;
}

export function cloneTypeReference(stsTypeRef: sts.TypeReferenceContext): sts.TypeReferenceContext {
    let stsTypeRefClone = new sts.TypeReferenceContext(undefined, 0);

    // Clone type reference parts.
    for (let stsTypeRefPart of stsTypeRef.typeReferencePart()) {
        let stsTypeRefPartClone = new sts.TypeReferencePartContext(stsTypeRefClone, 0);

        stsTypeRefPartClone.addChild(cloneQualifiedName(stsTypeRefPart.qualifiedName()));

        let stsTypeArgs = stsTypeRefPart.typeArguments();
        if (stsTypeArgs) stsTypeRefPartClone.addChild(cloneTypeArguments(stsTypeArgs));

        stsTypeRefClone.addChild(stsTypeRefPartClone);
    }

    return stsTypeRefClone;
}

export function cloneQualifiedName(stsQualifiedName: sts.QualifiedNameContext): sts.QualifiedNameContext {
    let stsQualifiedNameClone = new sts.QualifiedNameContext(undefined, 0);

    // Clone component identifiers.
    for (let stsIdentifier of stsQualifiedName.Identifier()) {
        stsQualifiedNameClone.addChild(NodeBuilder.terminalIdentifier(stsIdentifier.text));
    }

    return stsQualifiedNameClone;
}

export function cloneIntersectionType(stsIntersectionType: sts.IntersectionTypeContext): sts.IntersectionTypeContext {
    let stsIntersectionTypeClone = new sts.IntersectionTypeContext(undefined, 0);

    // Clone component type references.
    for (let stsTypeRef of stsIntersectionType.typeReference()) {
        stsIntersectionTypeClone.addChild(cloneTypeReference(stsTypeRef));
    }

    return stsIntersectionTypeClone;
}

export function cloneArrayType(stsArrayType: sts.ArrayTypeContext): sts.ArrayTypeContext {
    let stsArrayTypeClone = new sts.ArrayTypeContext(undefined, 0);

    // Clone element type.
    let stsTypeRef = stsArrayType.typeReference();
    let stsPredefinedType = stsArrayType.predefinedType();
    let stsFunctionType = stsArrayType.functionType();
    if (stsPredefinedType) {
        stsArrayTypeClone.addChild(clonePredefinedType(stsPredefinedType));
    }
    else if (stsTypeRef) {
        stsArrayTypeClone.addChild(cloneTypeReference(stsTypeRef));
    }
    else if (stsFunctionType) {
        stsArrayTypeClone.addChild(cloneFunctionType(stsFunctionType));
    }
    else {
        let stsNullableType = stsArrayType.nullableType();
        stsArrayTypeClone.addChild(cloneNullableType(stsNullableType));
    }

    // Add dimensions.
    let numDims = stsArrayType.OpenBracket().length;
    for (let i = 0; i < numDims; ++i) {
        stsArrayTypeClone.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.OpenBracket));
        stsArrayTypeClone.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.CloseBracket));
    }

    return stsArrayTypeClone;
}

export function cloneTypeArguments(stsTypeArgs: sts.TypeArgumentsContext): sts.TypeArgumentsContext {
    let stsTypeArgsClone = new sts.TypeArgumentsContext(undefined, 0);

    // Create new type argument list.
    let stsTypeArgsList = new sts.TypeArgumentListContext(stsTypeArgsClone, 0);
    stsTypeArgsClone.addChild(stsTypeArgsList);

    // Clone type arguments.
    for (let stsTypeArg of stsTypeArgs.typeArgumentList().typeArgument()) {
        let stsTypeArgClone = new sts.TypeArgumentContext(stsTypeArgsList, 0);

        // Clone type argument's type.
        let stsTypeRef = stsTypeArg.typeReference();
        let stsArrayType = stsTypeArg.arrayType();
        let stsFunctionType = stsTypeArg.functionType();
        let stsWilcardType = stsTypeArg.wildcardType();
        if (stsTypeRef) {
            stsTypeArgClone.addChild(cloneTypeReference(stsTypeRef));
        }
        else if (stsArrayType) {
            stsTypeArgClone.addChild(cloneArrayType(stsArrayType));
        }
        else if (stsFunctionType) {
            stsTypeArgClone.addChild(cloneFunctionType(stsFunctionType));
        }
        else if (stsWilcardType) {
            stsTypeArgClone.addChild(cloneWildcardType(stsWilcardType));
        }
        else {
            let stsNullableType = stsTypeArg.nullableType();
            stsTypeArgClone.addChild(cloneNullableType(stsNullableType));
        }

        stsTypeArgsList.addChild(stsTypeArgClone);
    }

    return stsTypeArgsClone;
}

// Not exported as wildcard types occur only in type argument context, i.e.
// this function will only be used by cloneTypeArguments function above.
function cloneWildcardType(stsWilcardType: sts.WildcardTypeContext): sts.WildcardTypeContext {
    let stsWilcardTypeClone = new sts.WildcardTypeContext(undefined, 0);

    // Clone in/out keyword.
    let stsIdentifier = stsWilcardType.Identifier();
    stsWilcardTypeClone.addChild(NodeBuilder.terminalIdentifier(stsIdentifier.text));

    // Clone bound type, if exists.
    let stsTypeRef = stsWilcardType.typeReference();
    if (stsTypeRef) {
        stsWilcardTypeClone.addChild(cloneTypeReference(stsTypeRef));
    }

    return stsWilcardTypeClone;
}

export function cloneFunctionType(stsFunctionType: sts.FunctionTypeContext): sts.FunctionTypeContext {
    let stsFunctionTypeClone = new sts.FunctionTypeContext(undefined, 0);

    // Clone parameter list, if exists.
    let stsParamList = stsFunctionType.parameterList();
    if (stsParamList) stsFunctionTypeClone.addChild(cloneParameterList(stsParamList));

    // Clone return type.
    let stsTypeAnno = stsFunctionType.typeAnnotation();
    stsFunctionTypeClone.addChild(cloneTypeAnnotation(stsTypeAnno));

    // Clone throws/rethrows keyword, if exists.
    let stsThrowsAnno = stsFunctionType.throwsAnnotation();
    if (stsThrowsAnno) stsFunctionTypeClone.addChild(cloneThrowsAnnotation(stsThrowsAnno));

    return stsFunctionTypeClone;
}

export function cloneNullableType(stsNullableType: sts.NullableTypeContext): sts.NullableTypeContext {
    let stsNullableTypeClone = new sts.NullableTypeContext(undefined, 0);

    // Clone predefined type, if exists.
    let stsPredefinedType = stsNullableType.predefinedType();
    if (stsPredefinedType) {
        stsNullableTypeClone.addChild(clonePredefinedType(stsPredefinedType));
        return stsNullableTypeClone;
    }

    // Clone type reference, if exists.
    let stsTypeRef = stsNullableType.typeReference();
    if (stsTypeRef) {
        stsNullableTypeClone.addChild(cloneTypeReference(stsTypeRef));
        return stsNullableTypeClone;
    }

    // Clone function type, if exists.
    let stsFunctionType = stsNullableType.functionType();
    if (stsFunctionType) {
        stsNullableTypeClone.addChild(cloneFunctionType(stsFunctionType));
        return stsNullableTypeClone;
    }

    // Clone array type, if exists.
    let stsArrayType = stsNullableType.arrayType();
    if (stsArrayType) {
        stsNullableTypeClone.addChild(cloneArrayType(stsArrayType));
        return stsNullableTypeClone;
    }

    // Clone wildcard type.
    let stsWilcardType = stsNullableType.wildcardType();
    stsNullableTypeClone.addChild(cloneWildcardType(stsWilcardType));
    return stsNullableTypeClone;
}