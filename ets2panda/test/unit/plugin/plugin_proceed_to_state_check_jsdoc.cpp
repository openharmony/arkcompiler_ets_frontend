/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>

#include "os/library_loader.h"

#include "public/es2panda_lib.h"
#include "util.h"

// NOLINTBEGIN

static es2panda_Impl *impl = nullptr;
static bool testResult = true;

// Note: namespace declaration and enum declaration will be lowered to class definition before checker.
static std::map<std::string, es2panda_AstNode *> classMap = {{"A", nullptr},
                                                             {"B", nullptr},
                                                             {"JsDocClass", nullptr},
                                                             {"JsDocClassOutside", nullptr},
                                                             {"JsDocClassDefault", nullptr},
                                                             {"JsdocNS", nullptr},
                                                             {"JsdocInnerNS", nullptr},
                                                             {"EM1", nullptr}};

static std::map<std::string, es2panda_AstNode *> interfaceMap = {{"JsdocInterface", nullptr},
                                                                 {"JsdocInterfaceOutside", nullptr}};

// Note: the interface property will be lowered to "getter" and "setter" before check, they will be found in methodMap.
static std::map<std::string, es2panda_AstNode *> methodMap = {
    {"interfaceFoo1", nullptr},  {"interfaceFoo2", nullptr},  {"interfaceFoo3", nullptr},  {"interfaceFoo4", nullptr},
    {"classFoo1", nullptr},      {"classFoo2", nullptr},      {"classFoo3", nullptr},      {"interfaceProp1", nullptr},
    {"interfaceProp2", nullptr}, {"interfaceProp3", nullptr}, {"interfaceProp4", nullptr}, {"jsDocFunc", nullptr}};

// Note: the variableDecl witll be transferred to property of ETSGLOBAL after lowerings.
static std::map<std::string, es2panda_AstNode *> propertyMap = {
    {"classProp1", nullptr}, {"classProp2", nullptr}, {"classProp3", nullptr}, {"jsdocVal1", nullptr},
    {"jsdocVal2", nullptr},  {"em1Prop1", nullptr},   {"em1Prop2", nullptr}};

static std::map<std::string, es2panda_AstNode *> annotationMap = {
    {"myAnno", nullptr}, {"myAnnoWithAnno", nullptr}, {"exportAnno", nullptr}};

static std::map<std::string, es2panda_AstNode *> etsParamsMap = {{"fooP1", nullptr}, {"fooP2", nullptr}};

static es2panda_AstNode *typeAlias = nullptr;
static es2panda_AstNode *indexerClass = nullptr;
static std::map<std::string, es2panda_AstNode *> indexerTransferredAccessor = {{"$_get", nullptr}, {"$_set", nullptr}};

static std::string g_source = R"(/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

@interface myMultiAnno {}

/**
 * ==== my Annotation jsdoc ====
 * @param1 preStr { p } behindStr
 * @param2 preStr {} behindStr
 */
@interface myAnno {}

/**
 * ==== my Annotation With Annotation jsdoc ====
 * @param1 preStr { p } behindStr
 * @param2 preStr {} behindStr
*/
@Retention({policy: "SOURCE"})
@interface myAnnoWithAnno {}

/**
 * ==== export Annotation jsdoc ====
 * @param1 preStr { p } behindStr
 * @param2 preStr {} behindStr
*/
export declare @interface exportAnno {}

/**
 * ==== export declare class A ====
 * @param1 {} behindStr
 * @param2 preStr { p }
*/
@myAnno
export declare class A {}

/**
 * ==== export abstract class B ====
 * @param1 {} behindStr
 * @param2 preStr { p }
*/
export declare abstract class B {}

declare class IndexerClass {
    /**
    * ==== ambient indexer jsdoc ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    [idx: number] : string
}

/**
 * ==== export enum EM1 ====
 * @param1 {} behindStr
 * @param2 preStr { p }
*/
export declare enum EM1 {
    /**
     * ==== enum prop1 jsdoc ====
     * @param1 {} behindStr
     * @param2 preStr { p }
    */
    em1Prop1 = 1,

    /**
     * ==== enum prop2 jsdoc ====
     * @param1 {} behindStr
     * @param2 preStr { p }
    */
    em1Prop2 = 2
}

/**
* ==== JsdocNS ====
* @param1 {} behindStr
* @param2 preStr { p }
*/
namespace JsdocNS {
  /**
  * ==== JsdocInterface ====
  * @param1 {} behindStr
  * @param2 preStr { p }
  */
  export interface JsdocInterface {
    /**
    * ==== interfaceFoo1 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    interfaceFoo1():void

    /**
    * ==== interfaceFoo2 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    interfaceFoo2():void

    /**
    * ==== private interfaceProp1 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    private interfaceProp1:number

    /**
    * ==== interfaceProp2 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    interfaceProp2:number | string[]
  }

  /**
  * ==== JsDocClass ====
  * @param1 {} behindStr
  * @param2 preStr { p }
  */
  export class JsDocClass {
    /**
    * ==== classFoo1 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    classFoo1():void {}

    /**
    * ==== private classProp1 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    private classProp1:number = 0;
  }

  /**
  * ==== JsdocInnerNS ====
  * @param1 {} behindStr
  * @param2 preStr { p }
  * @param3 preStr { p } behindStr
  */
  namespace JsdocInnerNS {}
}
/**
 * ==== JsdocInterfaceOutside ====
 * @param1 {} behindStr
 * @param2 preStr { p }
 */
export declare interface JsdocInterfaceOutside {
    /**
    * ==== interfaceFoo3 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    interfaceFoo3():void

    /**
    * ==== interfaceProp3 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    interfaceProp3:number

    /**
    * ==== interfaceFoo4 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    interfaceFoo4():void

    /**
    * ==== interfaceProp4 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    interfaceProp4:number
}

/**
* ==== JsDocClassDefault with multi-anno ====
* @param1 {} behindStr
* @param2 preStr { p }
*/
@myMultiAnno
@myAnno
export default class JsDocClassDefault {}

/**
* ==== JsDocClassOutside jsdoc1 ====
* @param7
*/
/**
* ==== JsDocClassOutside jsdoc2 ====
* @param1 {} behindStr
* @param2 preStr { p }
*/
export class JsDocClassOutside {
    /**
    * ==== classFoo2 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    classFoo2():void {}

    /**
    * ==== classFoo3 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    classFoo3():void {}

    /**
    * ==== public classProp2 jsdoc1 ====
    * @param7
    */

    /**
    * ==== public classProp2 jsdoc2 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    public classProp2:number = 0;

    /**
    * ==== classProp3 ====
    * @param1 {} behindStr
    * @param2 preStr { p }
    */
    classProp3:number = 0;
}

/**
* ==== function decl jsdoc ====
* @param1 {} behindStr
* @param2 preStr { p }
*/
function jsDocFunc(
/**
 * ==== function param p1 jsdoc ====
 * @param1 {} behindStr
 * @param2 preStr { p }
*/ fooP1: number,

/**
 * ==== function param p2 jsdoc ====
 * @param1 {} behindStr
 * @param2 preStr { p }
*/ fooP2: string): void {}

/**
* ==== typeAlas jsdoc ====
* @param1 {} behindStr
* @param2 preStr { p }
*/
type typeAlias = 'somexx3'

/**
 * ==== variable decl ====
 * @param1 {} behindStr
 * @param2 preStr { p }
 */
let jsdocVal1:string = "ssss"

/**
 * ==== variable decl with annotation ====
 * @param1 {} behindStr
 * @param2 preStr { p }
 */
@myAnnoWithAnno
let jsdocVal2:string = "ssss"
)";

static void FindAnnotationDecl(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsAnnotationDeclaration(ast)) {
        return;
    }
    auto *ident = impl->AnnotationDeclarationGetBaseNameConst(ctx, ast);
    if (ident == nullptr) {
        return;
    }
    auto name = std::string(impl->IdentifierName(ctx, ident));
    if (annotationMap.find(name) != annotationMap.end()) {
        annotationMap[name] = ast;
    }
}

static void FindClass(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsClassDefinition(ast)) {
        return;
    }
    auto *ident = impl->ClassDefinitionIdent(ctx, ast);
    if (ident == nullptr) {
        return;
    }
    auto name = std::string(impl->IdentifierName(ctx, ident));
    if (classMap.find(name) != classMap.end()) {
        classMap[name] = ast;
    }

    if (name == "IndexerClass") {
        indexerClass = ast;
    }
}

static void FindInterface(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsTSInterfaceDeclaration(ast)) {
        return;
    }
    auto *ident = impl->TSInterfaceDeclarationId(ctx, ast);
    if (ident == nullptr) {
        return;
    }
    auto name = std::string(impl->IdentifierName(ctx, ident));
    if (interfaceMap.find(name) != interfaceMap.end()) {
        interfaceMap[name] = ast;
    }
}

static void FindMethodDef(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsMethodDefinition(ast)) {
        return;
    }
    auto *function = impl->MethodDefinitionFunction(ctx, ast);
    if (function == nullptr) {
        return;
    }

    auto *ident = impl->ScriptFunctionId(ctx, function);
    if (ident == nullptr) {
        return;
    }
    auto name = std::string(impl->IdentifierName(ctx, ident));
    if (methodMap.find(name) != methodMap.end()) {
        methodMap[name] = ast;
    }
}

static void FindETSParamDecl(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsETSParameterExpression(ast)) {
        return;
    }
    auto *ident = impl->ETSParameterExpressionIdent(ctx, ast);
    if (ident == nullptr) {
        return;
    }
    auto name = std::string(impl->IdentifierName(ctx, ident));
    if (etsParamsMap.find(name) != etsParamsMap.end()) {
        etsParamsMap[name] = ast;
    }
}

static void FindClassElement(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsClassProperty(ast)) {
        return;
    }
    auto *ident = impl->ClassElementId(ctx, ast);
    if (ident == nullptr) {
        return;
    }

    auto name = std::string(impl->IdentifierName(ctx, ident));
    if (propertyMap.find(name) != propertyMap.end()) {
        propertyMap[name] = ast;
    }
}

static void FindTypeAliasDecl(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsTSTypeAliasDeclaration(ast)) {
        return;
    }
    auto *ident = impl->TSTypeAliasDeclarationId(ctx, ast);
    if (ident == nullptr) {
        return;
    }
    auto name = impl->IdentifierName(ctx, ident);
    if (std::string(name) == "typeAlias") {
        typeAlias = ast;
    }
}

// Note: should be called after `FindClass`
static void FindIndexerTransferredGetterSetter(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsMethodDefinition(ast)) {
        return;
    }
    auto *function = impl->MethodDefinitionFunction(ctx, ast);
    if (function == nullptr) {
        return;
    }

    auto *ident = impl->ScriptFunctionId(ctx, function);
    if (ident == nullptr) {
        return;
    }
    auto name = std::string(impl->IdentifierName(ctx, ident));
    if (indexerTransferredAccessor.find(name) != indexerTransferredAccessor.end()) {
        indexerTransferredAccessor[name] = ast;
    }
}

static void FindTargetAst(es2panda_Context *context, es2panda_AstNode *ast)
{
    impl->AstNodeForEach(ast, FindClass, context);
    impl->AstNodeForEach(ast, FindInterface, context);
    impl->AstNodeForEach(ast, FindMethodDef, context);
    impl->AstNodeForEach(ast, FindClassElement, context);
    impl->AstNodeForEach(ast, FindTypeAliasDecl, context);
    impl->AstNodeForEach(ast, FindAnnotationDecl, context);
    impl->AstNodeForEach(ast, FindETSParamDecl, context);
    impl->AstNodeForEach(indexerClass, FindIndexerTransferredGetterSetter, context);
}

static bool TestJSDoc(es2panda_Context *context)
{
    auto *program = impl->ContextProgram(context);
    auto *entryAst = impl->ProgramAst(context, program);
    if (entryAst == nullptr) {
        return false;
    }
    FindTargetAst(context, entryAst);

    std::cout << impl->GetLicenseFromRootNode(context, entryAst) << std::endl;

    for (const auto &[name, targetAst] : classMap) {
        std::cout << impl->JsdocStringFromDeclaration(context, targetAst) << std::endl;
    }

    for (const auto &[name, targetAst] : interfaceMap) {
        std::cout << impl->JsdocStringFromDeclaration(context, targetAst) << std::endl;
    }

    for (const auto &[name, targetAst] : methodMap) {
        std::cout << impl->JsdocStringFromDeclaration(context, targetAst) << std::endl;
    }

    for (const auto &[name, targetAst] : indexerTransferredAccessor) {
        std::cout << impl->JsdocStringFromDeclaration(context, targetAst) << std::endl;
    }

    for (const auto &[name, targetAst] : propertyMap) {
        std::cout << impl->JsdocStringFromDeclaration(context, targetAst) << std::endl;
    }

    impl->JsdocStringFromDeclaration(context, typeAlias);

    for (const auto &[name, targetAst] : annotationMap) {
        std::cout << impl->JsdocStringFromDeclaration(context, targetAst) << std::endl;
    }

    for (const auto &[name, targetAst] : etsParamsMap) {
        std::cout << impl->JsdocStringFromDeclaration(context, targetAst) << std::endl;
    }

    return testResult;
}

int main(int argc, char **argv)
{
    std::map<es2panda_ContextState, std::vector<std::function<bool(es2panda_Context *)>>> testFunctions;
    testFunctions[ES2PANDA_STATE_CHECKED] = {TestJSDoc};
    ProccedToStatePluginTestData data = {argc, argv, &impl, testFunctions, true, g_source};
    return RunAllStagesWithTestFunction(data);
}

// NOLINTEND