/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
    ArkMethod,
    ArkAssignStmt,
    FieldSignature,
    Stmt,
    Scene,
    Value,
    DVFGBuilder,
    CallGraph,
    ArkParameterRef,
    ArkInstanceFieldRef,
    ArkNamespace,
    Local,
    ClassType,
    ClassSignature,
    Type,
    BooleanType,
    FunctionType,
    AnyType,
    MethodSignature,
    UnknownType,
    GenericType,
    NumberType,
    ArrayType,
    MethodSubSignature,
    ArkInvokeStmt,
    AbstractInvokeExpr,
    ArkInstanceInvokeExpr,
    ArkPtrInvokeExpr,
    ImportInfo,
    UnionType,
    FileSignature,
    ArkStaticInvokeExpr,
    UndefinedType,
    VoidType,
} from 'arkanalyzer/lib';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, MatcherCallback } from '../../Index';
import { IssueReport } from '../../model/Defects';
import { DVFG, DVFGNode } from 'arkanalyzer/lib/VFG/DVFG';
import { CALL_DEPTH_LIMIT, getGlobalsDefineInDefaultMethod, GlobalCallGraphHelper } from './Utils';
import { WarnInfo } from '../../utils/common/Utils';
import { ArkClass } from 'arkanalyzer/lib/core/model/ArkClass';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';
import { MethodParameter } from 'arkanalyzer/lib/core/model/builder/ArkMethodBuilder';
import { AbstractFieldRef, ArkReturnStmt } from 'arkanalyzer';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'DeprecatedBuiltInAPICheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
};

enum APIBaseCategory {
    Array = 'Array',
    Set = 'Set',
    Map = 'Map',
}

class DeprecatedAPIInfo {
    constructor(
        public base: APIBaseCategory,
        public name: string,
        public isStatic: boolean,
        public returnType?: Type, // return Type为undefined时表示不关心API的返回值
        public params?: Type[], // return Type为undefined时表示不关心API的形参，应该是整个API都被废弃，而非某一重载形态
        public targetParamIndex?: number // 若isStatic为tue，说明是静态接口，需要提供查找接口的第几个param是否来源arkts1.2，编号从0开始，不提供则查找base的来源
    ) {}
}

class APIBasicType {
    static readonly genericTypeT = new GenericType('T');
    static readonly genericTypeU = new GenericType('U');
    static readonly genericTypeV = new GenericType('V');
    static readonly genericTypeK = new GenericType('K');
    static readonly genericTypeS = new GenericType('S');
    static readonly arrayT = new ArrayType(this.genericTypeT, 1);
    static readonly arrayU = new ArrayType(this.genericTypeU, 1);
    static readonly unknownType = UnknownType.getInstance();
    static readonly numberType = NumberType.getInstance();
    static readonly booleanType = BooleanType.getInstance();
    static readonly anyType = AnyType.getInstance();
    static readonly undefinedType = UndefinedType.getInstance();
    static readonly voidType = VoidType.getInstance();
}

class APIComplicatedType {
    static readonly anonyMethodName = 'anonymous';
    static readonly predicateFunctionType = this.createPredicateFunctionType();
    static readonly predicateFunction1Type = this.createPredicateFunction1Type();
    static readonly concatItemType = this.createConcatItemType();
    static readonly mapfnFunctionType = this.createMapfnFunctionType();
    static readonly ArrayLikeType = new ClassType(new ClassSignature('ArrayLike', FileSignature.DEFAULT));
    static readonly IterableType = new ClassType(new ClassSignature('Iterable', FileSignature.DEFAULT));
    static readonly SetType = new ClassType(new ClassSignature('Set', FileSignature.DEFAULT));
    static readonly MapType = new ClassType(new ClassSignature('Map', FileSignature.DEFAULT));
    static readonly setCallbackFnFunctionType = this.createSetCallbackFnFunctionType();
    static readonly mapCallbackFnFunctionType = this.createMapCallbackFnFunctionType();

    // 对于参数类型一致，但是参数名称不同、返回值类型不同的FunctionType，视为同一个，不重新创建。因为FunctionType类型匹配的时候仅匹配参数类型
    // 不同的API，仅形参为lambda函数且该lambda函数的返回值不同，例如unknown和value is S类型谓词形式，视为同一个API
    private static createPredicateFunctionType(): FunctionType {
        const predicateValueParam = new MethodParameter();
        predicateValueParam.setName('value');
        predicateValueParam.setType(APIBasicType.genericTypeT);
        const predicateIndexParam = new MethodParameter();
        predicateIndexParam.setName('index');
        predicateIndexParam.setType(APIBasicType.numberType);
        const predicateArrayParam = new MethodParameter();
        predicateArrayParam.setName('array');
        predicateArrayParam.setType(APIBasicType.arrayT);
        const predicateMethodSubSignature = new MethodSubSignature(
            this.anonyMethodName,
            [predicateValueParam, predicateIndexParam, predicateArrayParam],
            APIBasicType.unknownType
        );
        return new FunctionType(new MethodSignature(ClassSignature.DEFAULT, predicateMethodSubSignature));
    }

    private static createPredicateFunction1Type(): FunctionType {
        const predicateThisParam = new MethodParameter();
        predicateThisParam.setName('this');
        predicateThisParam.setType(APIBasicType.voidType);
        const predicateValueParam = new MethodParameter();
        predicateValueParam.setName('value');
        predicateValueParam.setType(APIBasicType.genericTypeT);
        const predicateIndexParam = new MethodParameter();
        predicateIndexParam.setName('index');
        predicateIndexParam.setType(APIBasicType.numberType);
        const predicateObjParam = new MethodParameter();
        predicateObjParam.setName('obj');
        predicateObjParam.setType(APIBasicType.arrayT);
        const predicateMethodSubSignature = new MethodSubSignature(
            this.anonyMethodName,
            [predicateThisParam, predicateValueParam, predicateIndexParam, predicateObjParam],
            APIBasicType.booleanType
        );
        return new FunctionType(new MethodSignature(ClassSignature.DEFAULT, predicateMethodSubSignature));
    }

    private static createConcatItemType(): UnionType {
        return new UnionType([APIBasicType.genericTypeT, new ClassType(new ClassSignature('ConcatArray', FileSignature.DEFAULT))]);
    }

    private static createMapfnFunctionType(): FunctionType {
        const mapfnParamV = new MethodParameter();
        mapfnParamV.setName('v');
        mapfnParamV.setType(APIBasicType.genericTypeT);
        const mapfnParamK = new MethodParameter();
        mapfnParamK.setName('k');
        mapfnParamK.setType(APIBasicType.numberType);
        const mapfnMethodSubSignature = new MethodSubSignature(this.anonyMethodName, [mapfnParamV, mapfnParamK], APIBasicType.genericTypeU);
        return new FunctionType(new MethodSignature(ClassSignature.DEFAULT, mapfnMethodSubSignature));
    }

    private static createSetCallbackFnFunctionType(): FunctionType {
        const callbackFnValueParam = new MethodParameter();
        callbackFnValueParam.setName('value');
        callbackFnValueParam.setType(APIBasicType.genericTypeT);
        const callbackFnValue2Param = new MethodParameter();
        callbackFnValue2Param.setName('value2');
        callbackFnValue2Param.setType(APIBasicType.genericTypeT);
        const callbackFnSetParam = new MethodParameter();
        callbackFnSetParam.setName('set');
        callbackFnSetParam.setType(this.SetType);
        const predicateMethodSubSignature = new MethodSubSignature(
            this.anonyMethodName,
            [callbackFnValueParam, callbackFnValue2Param, callbackFnSetParam],
            APIBasicType.voidType
        );
        return new FunctionType(new MethodSignature(ClassSignature.DEFAULT, predicateMethodSubSignature));
    }

    private static createMapCallbackFnFunctionType(): FunctionType {
        const callbackFnValueParam = new MethodParameter();
        callbackFnValueParam.setName('value');
        callbackFnValueParam.setType(APIBasicType.genericTypeV);
        const callbackFnKeyParam = new MethodParameter();
        callbackFnKeyParam.setName('key');
        callbackFnKeyParam.setType(APIBasicType.genericTypeK);
        const callbackFnMapParam = new MethodParameter();
        callbackFnMapParam.setName('map');
        callbackFnMapParam.setType(this.MapType);
        const predicateMethodSubSignature = new MethodSubSignature(
            this.anonyMethodName,
            [callbackFnValueParam, callbackFnKeyParam, callbackFnMapParam],
            APIBasicType.voidType
        );
        return new FunctionType(new MethodSignature(ClassSignature.DEFAULT, predicateMethodSubSignature));
    }
}

class DeprecatedAPIList {
    static readonly DeprecatedAPIs: DeprecatedAPIInfo[] = [
        this.createArrayEveryAPI1(),
        this.createArrayFilterAPI1(),
        this.createArrayFindAPI1(),
        this.createArrayFindAPI2(),
        this.createArrayFindIndexAPI(),
        this.createArrayForEachAPI(),
        this.createArrayMapAPI(),
        this.createArraySomeAPI(),
        this.createArrayConcatAPI(),
        this.createArrayFlatAPI(),
        this.createArrayFlatMapAPI(),
        this.createArrayFromArrayLikeAPI(),
        this.createArrayFromIterableAndArrayLikeAPI(),
        this.createSetForEachAPI(),
        this.createMapForEachAPI(),
        this.createArraySymbolIteratorAPI(),
        this.createSetSymbolIteratorAPI(),
        this.createMapSymbolIteratorAPI(),
    ];

    private static createArrayEveryAPI1(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'every', false, APIBasicType.booleanType, [
            APIComplicatedType.predicateFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createArrayFilterAPI1(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'filter', false, APIBasicType.arrayT, [
            APIComplicatedType.predicateFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createArrayFindAPI1(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'find', false, new UnionType([APIBasicType.genericTypeT, APIBasicType.undefinedType]), [
            APIComplicatedType.predicateFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createArrayFindAPI2(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'find', false, new UnionType([APIBasicType.genericTypeS, APIBasicType.undefinedType]), [
            APIComplicatedType.predicateFunction1Type,
            APIBasicType.anyType,
        ]);
    }

    private static createArrayFindIndexAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'findIndex', false, APIBasicType.numberType, [
            APIComplicatedType.predicateFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createArrayForEachAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'forEach', false, APIBasicType.voidType, [
            APIComplicatedType.predicateFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createArrayMapAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'map', false, APIBasicType.arrayU, [
            APIComplicatedType.predicateFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createArraySomeAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'some', false, APIBasicType.booleanType, [
            APIComplicatedType.predicateFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createArrayConcatAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'concat', false, APIBasicType.arrayT, [new ArrayType(APIComplicatedType.concatItemType, 1)]);
    }

    private static createArrayFlatAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'flat', false);
    }

    private static createArrayFlatMapAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'flatMap', false);
    }

    private static createArrayFromArrayLikeAPI(): DeprecatedAPIInfo {
        const fromParams = [APIComplicatedType.ArrayLikeType, APIComplicatedType.mapfnFunctionType, APIBasicType.anyType];
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'from', true, APIBasicType.arrayU, fromParams, 0);
    }

    private static createArrayFromIterableAndArrayLikeAPI(): DeprecatedAPIInfo {
        const fromParams = [
            new UnionType([APIComplicatedType.ArrayLikeType, APIComplicatedType.IterableType]),
            APIComplicatedType.mapfnFunctionType,
            APIBasicType.anyType,
        ];
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'from', true, APIBasicType.arrayU, fromParams, 0);
    }

    private static createSetForEachAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Set, 'forEach', false, APIBasicType.voidType, [
            APIComplicatedType.setCallbackFnFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createMapForEachAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Map, 'forEach', false, APIBasicType.voidType, [
            APIComplicatedType.mapCallbackFnFunctionType,
            APIBasicType.anyType,
        ]);
    }

    private static createArraySymbolIteratorAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Array, 'Symbol.iterator', false);
    }

    private static createSetSymbolIteratorAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Set, 'Symbol.iterator', false);
    }

    private static createMapSymbolIteratorAPI(): DeprecatedAPIInfo {
        return new DeprecatedAPIInfo(APIBaseCategory.Map, 'Symbol.iterator', false);
    }
}

export class InteropDeprecatedBuiltInAPICheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];
    private cg: CallGraph;
    private dvfg: DVFG;
    private dvfgBuilder: DVFGBuilder;
    private scene: Scene;
    private visited: Set<ArkMethod> = new Set();

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: undefined,
            callback: this.check,
        };
        return [matchBuildCb];
    }

    public check = (scene: Scene): void => {
        this.scene = scene;
        this.cg = GlobalCallGraphHelper.getCGInstance(scene);

        this.dvfg = new DVFG(this.cg);
        this.dvfgBuilder = new DVFGBuilder(this.dvfg, scene);

        for (let arkFile of scene.getFiles()) {
            // 此规则仅对arkts1.1进行检查
            if (!(arkFile.getLanguage() === Language.ARKTS1_1)) {
                continue;
            }
            const defaultMethod = arkFile.getDefaultClass().getDefaultArkMethod();
            let globalVarMap: Map<string, Stmt[]> = new Map();
            if (defaultMethod) {
                this.dvfgBuilder.buildForSingleMethod(defaultMethod);
                globalVarMap = getGlobalsDefineInDefaultMethod(defaultMethod);
            }
            for (let arkClass of arkFile.getClasses()) {
                this.processArkClass(arkClass, globalVarMap);
            }
            for (let namespace of arkFile.getAllNamespacesUnderThisFile()) {
                this.processNameSpace(namespace, globalVarMap);
            }
        }
    };

    public processArkClass(arkClass: ArkClass, globalVarMap: Map<string, Stmt[]>): void {
        this.processArkMethod(arkClass.getInstanceInitMethod(), globalVarMap);
        this.processArkMethod(arkClass.getStaticInitMethod(), globalVarMap);
        for (let mtd of arkClass.getMethods()) {
            this.processArkMethod(mtd, globalVarMap);
        }
    }

    public processNameSpace(namespace: ArkNamespace, globalVarMap: Map<string, Stmt[]>): void {
        for (let ns of namespace.getNamespaces()) {
            this.processNameSpace(ns, globalVarMap);
        }
        for (let arkClass of namespace.getClasses()) {
            this.processArkClass(arkClass, globalVarMap);
        }
    }

    public processArkMethod(target: ArkMethod, globalVarMap: Map<string, Stmt[]>): void {
        const stmts = target.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            // 查找到DeprecatedAPIs中的builtIn的API调用语句为sink点，从该点开始进行逆向数据流分析，分析base是否为arkts1.2中声明的对象实例或其引用
            const targetLocal = this.getTargetLocalOfDeprecatedAPICall(stmt);
            if (targetLocal === null) {
                continue;
            }

            // 从base的最近一次赋值语句开始，使用逆向数据流进行查找
            let checkStmt = this.getLastAssignStmt(targetLocal, stmt);
            if (checkStmt === null) {
                checkStmt = this.checkTargetLocalAsGlobal(target, stmt, targetLocal, globalVarMap);
            }
            if (checkStmt === null) {
                continue;
            }

            if (!this.visited.has(target)) {
                this.dvfgBuilder.buildForSingleMethod(target);
                this.visited.add(target);
            }

            let checkAll = { value: true };
            let visited: Set<Stmt> = new Set();
            if (this.checkFromStmt(checkStmt, globalVarMap, checkAll, visited)) {
                this.addIssueReport(stmt, targetLocal, checkAll.value);
            }
        }
    }

    private checkTargetLocalAsGlobal(targetMethod: ArkMethod, stmt: Stmt, targetLocal: Local, globalVarMap: Map<string, Stmt[]>): Stmt | null {
        const globalDefs = globalVarMap.get(targetLocal.getName());
        if (globalDefs === undefined) {
            const importInfos = targetMethod.getDeclaringArkClass().getDeclaringArkFile().getImportInfos();
            const importValue = this.isLocalFromImport(targetLocal, importInfos);
            if (importValue && importValue.getDeclaringStmt() !== null) {
                return importValue.getDeclaringStmt()!;
            }
            return null;
        }
        let lastLegalStmtLine = -1;
        let lastIllegalStmtLine = -1;
        for (const defStmt of globalDefs) {
            if (!this.visited.has(targetMethod)) {
                this.dvfgBuilder.buildForSingleMethod(targetMethod);
                this.visited.add(targetMethod);
            }

            let checkAll = { value: true };
            let visited: Set<Stmt> = new Set();

            const currStmtLine = defStmt.getOriginPositionInfo().getLineNo();
            if (this.checkFromStmt(defStmt, globalVarMap, checkAll, visited)) {
                if (currStmtLine > lastIllegalStmtLine) {
                    lastIllegalStmtLine = currStmtLine;
                }
            } else {
                if (currStmtLine > lastLegalStmtLine) {
                    lastLegalStmtLine = currStmtLine;
                }
            }
        }
        if (lastIllegalStmtLine > lastLegalStmtLine) {
            this.addIssueReport(stmt, targetLocal);
        }
        return null;
    }

    private getLastAssignStmt(local: Local, currStmt: Stmt): Stmt | null {
        // 获取local变量在currStmt使用语句之前的最近一次赋值/声明语句，未找到表示直接来自于全局变量或import信息，则返回null
        const usedStmts = local.getUsedStmts();
        let currLine = currStmt.getOriginPositionInfo().getLineNo();
        let lastAssignStmt = local.getDeclaringStmt();
        for (const stmt of usedStmts) {
            if (stmt === currStmt || !(stmt instanceof ArkAssignStmt) || stmt.getLeftOp() !== local) {
                continue;
            }
            const line = stmt.getOriginPositionInfo().getLineNo();
            if (line < currLine) {
                lastAssignStmt = stmt;
                currLine = line;
            }
        }
        return lastAssignStmt;
    }

    private isLocalDefinedInStaticArkTS(local: Local): boolean {
        return local.getDeclaringStmt()?.getCfg().getDeclaringMethod().getLanguage() === Language.ARKTS1_2;
    }

    // 判断语句是否为废弃API接口的调用语句，若废弃接口仅为一系列重载中的某一种，需要判断这一具体重载形态，若是返回对应需要查找的Local对象，否则返回null
    private getTargetLocalOfDeprecatedAPICall(stmt: Stmt): Local | null {
        const invokeExpr = this.getInvokeExpr(stmt);
        if (invokeExpr === null) {
            return null;
        }
        if (invokeExpr instanceof ArkInstanceInvokeExpr) {
            const base = invokeExpr.getBase();
            if (this.isInstanceCallMethodInDeprecatedAPIs(base, stmt, invokeExpr.getMethodSignature(), invokeExpr.getArgs())) {
                return base;
            }
            // Array.from的API调用ArkAnalyzer也表示为ArkInstanceInvokeExpr，因为API定义里没有明确的static标识
            return this.getTargetLocalInArrayFrom(invokeExpr);
        } else if (invokeExpr instanceof ArkPtrInvokeExpr) {
            // TODO：可能存在ptr invoke的场景吗？
            return null;
        } else if (invokeExpr instanceof ArkStaticInvokeExpr) {
            // Symbol.iterator API 检测的Reflect.get场景，是static invoke
            return this.getTargetLocalInReflectGet(invokeExpr);
        }
        return null;
    }

    private getInvokeExpr(stmt: Stmt): AbstractInvokeExpr | null {
        if (!(stmt instanceof ArkAssignStmt) && !(stmt instanceof ArkInvokeStmt)) {
            return null;
        }

        if (stmt instanceof ArkInvokeStmt) {
            return stmt.getInvokeExpr();
        }

        const rightOp = stmt.getRightOp();
        if (rightOp instanceof AbstractInvokeExpr) {
            return rightOp;
        }
        return null;
    }

    private compareParamTypes(apiParams: Type[], callApiParams: MethodParameter[]): boolean {
        if (apiParams.length !== callApiParams.length) {
            return false;
        }
        for (let i = 0; i < apiParams.length; i++) {
            if (!this.isTypeMatch(apiParams[i], callApiParams[i].getType())) {
                return false;
            }
        }
        return true;
    }

    // 此函数仅用作Symbol.iterator API 检测的Reflect.get场景
    private getTargetLocalInReflectGet(staticInvokeExpr: ArkStaticInvokeExpr): Local | null {
        const method = staticInvokeExpr.getMethodSignature();
        const methodName = method.getMethodSubSignature().getMethodName();
        const namespaceName = method.getDeclaringClassSignature().getDeclaringNamespaceSignature()?.getNamespaceName();
        if (namespaceName !== 'Reflect' || methodName !== 'get') {
            return null;
        }

        const args = staticInvokeExpr.getArgs();
        if (args.length < 2) {
            return null;
        }
        const targetLocal = args[0];
        const apiCall = args[1];
        if (!(targetLocal instanceof Local) || !(apiCall instanceof Local)) {
            return null;
        }

        const declaringStmt = apiCall.getDeclaringStmt();
        if (declaringStmt === null || !(declaringStmt instanceof ArkAssignStmt)) {
            return null;
        }
        const rightOp = declaringStmt.getRightOp();
        if (!(rightOp instanceof ArkInstanceFieldRef)) {
            return null;
        }
        const fieldBaseName = rightOp.getBase().getName();
        const fieldName = rightOp.getFieldName();
        if (fieldBaseName !== 'Symbol' || fieldName !== 'iterator') {
            return null;
        }

        for (const api of DeprecatedAPIList.DeprecatedAPIs) {
            if (api.name !== 'Symbol.iterator') {
                continue;
            }
            if (api.base === APIBaseCategory.Array && targetLocal.getType() instanceof ArrayType) {
                return targetLocal;
            }
            if (api.base === APIBaseCategory.Set) {
                const localType = targetLocal.getType();
                if (localType instanceof ClassType && localType.getClassSignature().getClassName() === 'Set') {
                    return targetLocal;
                }
            }
            if (api.base === APIBaseCategory.Map) {
                const localType = targetLocal.getType();
                if (localType instanceof ClassType && localType.getClassSignature().getClassName() === 'Map') {
                    return targetLocal;
                }
            }
        }
        return null;
    }

    private getTargetLocalInArrayFrom(invokeExpr: ArkInstanceInvokeExpr): Local | null {
        const callApiMethod = invokeExpr.getMethodSignature();
        const callApiClass = callApiMethod.getDeclaringClassSignature();
        for (const api of DeprecatedAPIList.DeprecatedAPIs) {
            if (!api.isStatic) {
                continue;
            }
            if (api.name !== callApiMethod.getMethodSubSignature().getMethodName()) {
                continue;
            }
            // Array.from 形式的调用，from方法实际的class为ArrayConstructor
            if (api.base !== callApiClass.getClassName() && `${api.base}Constructor` !== callApiClass.getClassName()) {
                continue;
            }
            // 在本条规则检查范围内的static API的调用一定是带参数的，并且其中某个参数即为需要进行进一步查找的value
            if (api.params === undefined) {
                continue;
            }
            if (this.compareParamTypes(api.params, callApiMethod.getMethodSubSignature().getParameters())) {
                const args = invokeExpr.getArgs();
                // 形参匹配的情况下，进一步比较传入的实参，因为当前废弃接口大多数为去掉any类型的第二个可选参数
                // TODO：这里需要考虑如何做的更通用
                if (args.length !== api.params.length) {
                    continue;
                }
                const index = api.targetParamIndex;
                // 成功匹配到指定的API后，如果未提供下一步需要查找的目标param的index，则返回null。理论上不应该走到这个分支。
                if (index === undefined) {
                    logger.error(`Missing targetParamIndex, api: ${api.name}, category ${api.base}`);
                    return null;
                }

                if (args.length <= index) {
                    logger.error(`Invalid targetParamIndex ${index}, totally invoke args size ${args.length}, api: ${api.name}, category ${api.base}`);
                    return null;
                }
                const target = args[index];
                if (target instanceof Local) {
                    return target;
                }
                logger.error(`Need to handle non-local target ${target.getType().getTypeString()}`);
                return null;
            }
        }
        return null;
    }

    private isInstanceCallMethodInDeprecatedAPIs(callBase: Local, stmt: Stmt, callMethod: MethodSignature, args: Value[]): boolean {
        const callApiName = callMethod.getMethodSubSignature().getMethodName();
        const callApiParams = callMethod.getMethodSubSignature().getParameters();
        for (const api of DeprecatedAPIList.DeprecatedAPIs) {
            // 对于map[Symbol.iterator]这样的API调用，callApiName是临时变量，需要进一步匹配
            if (api.name !== callApiName) {
                continue;
            }
            // 对于for...of的语句，ArkAnalyzer会为其生成Symbol.iterator的调用语句，此处从源码中查找关键字以区分是源码中有还是自动生成的
            if (api.name === 'Symbol.iterator' && !stmt.getOriginalText()?.includes('Symbol.iterator')) {
                continue;
            }
            if (api.isStatic) {
                continue;
            }
            if (!this.isBaseTypeMatchAPIBase(api.base, callBase)) {
                continue;
            }

            // Array concat API ArkAnalyzer当前无法很好处理...items形式的入参，此处作为特例处理
            if (api.name === 'concat' && api.base === APIBaseCategory.Array) {
                return this.isMatchArrayConcatAPI(args);
            }

            const apiParams = api.params;
            if (apiParams === undefined) {
                return true;
            }
            let allParamTypeMatch = this.compareParamTypes(apiParams, callApiParams);
            if (allParamTypeMatch) {
                // 形参匹配的情况下，进一步比较传入的实参，因为当前废弃接口大多数为去掉any类型的第二个可选参数
                // TODO：这里需要考虑如何做的更通用
                if (args.length !== apiParams.length) {
                    continue;
                }
                return true;
            }
            // 形参类型不匹配的情形，可能是由于ArkAnalyzer的类型推导未能找到正确的API，需要根据实参类型进行二次匹配
            if (apiParams.length !== args.length) {
                continue;
            }
            allParamTypeMatch = true;
            for (let i = 0; i < apiParams.length; i++) {
                // 对于lambda函数作为参数类型，此处不严格校验lambda的参数类型，仅判断是否为FunctionType
                if (apiParams[i] instanceof FunctionType && args[i].getType() instanceof FunctionType) {
                    continue;
                }
                if (!this.isTypeMatch(apiParams[i], args[i].getType())) {
                    allParamTypeMatch = false;
                    break;
                }
            }
            if (allParamTypeMatch) {
                return true;
            }
        }
        return false;
    }

    // 判断入参是否都为数组，不允许有单个元素
    private isMatchArrayConcatAPI(args: Value[]): boolean {
        for (const arg of args) {
            if (!(arg.getType() instanceof ArrayType)) {
                return true;
            }
        }
        return false;
    }

    private isTypeMatch(apiType: Type, callApiType: Type): boolean {
        const apiTypeStr = apiType.getTypeString();
        const callApiTypeStr = callApiType.getTypeString();
        if (callApiType instanceof FunctionType && apiType instanceof FunctionType) {
            // 若类型为FunctionType，仅需匹配string中的形参部分
            const regex = /\(([^()]*)\)/;
            const apiMatch = apiTypeStr.match(regex);
            const callApiMatch = callApiTypeStr.match(regex);
            if (apiMatch === null || callApiMatch === null) {
                return false;
            }
            // 移除字符串中的类型的文件签名、类签名、泛型等信息后进行比较
            let apiParamsStr = apiMatch[0].replace(/@[^:]+:/, '').replace(/<[^>]+>/, '');
            let callApiParamsStr = callApiMatch[0].replace(/@[^:]+:/, '').replace(/<[^>]+>/, '');
            return apiParamsStr === callApiParamsStr;
        } else if (callApiType instanceof ClassType && apiType instanceof ClassType) {
            // 若类型为FunctionType，仅需匹配class name，因为apiTypeStr类型推导后有可能为@%unk/%unk: ArrayLike，而callApiTypeStr有明确的declaring file
            return callApiType.getClassSignature().getClassName() === apiType.getClassSignature().getClassName();
        } else if (apiType instanceof AnyType) {
            return true;
        } else {
            // 其他场景需严格判断字符串相等
            return apiTypeStr === callApiTypeStr;
        }
    }

    private isBaseTypeMatchAPIBase(apiBase: APIBaseCategory, callBase: Local): boolean {
        if (apiBase === APIBaseCategory.Array && callBase.getType() instanceof ArrayType) {
            return true;
        }
        if (apiBase === APIBaseCategory.Map) {
            const callBaseType = callBase.getType();
            return callBaseType instanceof ClassType && callBaseType.getClassSignature().getClassName() === 'Map';
        }
        if (apiBase === APIBaseCategory.Set) {
            const callBaseType = callBase.getType();
            return callBaseType instanceof ClassType && callBaseType.getClassSignature().getClassName() === 'Set';
        }
        return false;
    }

    private checkFromStmt(stmt: Stmt, globalVarMap: Map<string, Stmt[]>, checkAll: { value: boolean }, visited: Set<Stmt>, depth: number = 0): boolean {
        if (depth > CALL_DEPTH_LIMIT) {
            checkAll.value = false;
            return true;
        }
        const node = this.dvfg.getOrNewDVFGNode(stmt);
        let worklist: DVFGNode[] = [node];
        while (worklist.length > 0) {
            const current = worklist.shift()!;
            const currentStmt = current.getStmt();
            if (visited.has(currentStmt)) {
                continue;
            }
            visited.add(currentStmt);

            if (this.isLeftOpOrReturnOpDefinedInStaticArkTS(currentStmt)) {
                return true;
            }

            // 当前语句的右值是全局变量，查找全局变量的定义语句
            const gv = this.isRightOpGlobalVar(currentStmt);
            if (gv) {
                const globalDefs = globalVarMap.get(gv.getName());
                if (globalDefs === undefined) {
                    const importInfos = stmt.getCfg().getDeclaringMethod().getDeclaringArkFile().getImportInfos();
                    const importValue = this.isLocalFromImport(gv, importInfos);
                    if (importValue && importValue.getDeclaringStmt() !== null) {
                        worklist.push(this.dvfg.getOrNewDVFGNode(importValue.getDeclaringStmt()!));
                    }
                } else {
                    globalDefs.forEach(d => worklist.push(this.dvfg.getOrNewDVFGNode(d)));
                }
                continue;
            }

            // 当前语句的右值是函数返回值，查找调用函数的所有return语句
            const callsite = this.cg.getCallSiteByStmt(currentStmt);
            for (const cs of callsite) {
                const declaringMtd = this.cg.getArkMethodByFuncID(cs.calleeFuncID);
                if (!declaringMtd || !declaringMtd.getCfg()) {
                    continue;
                }
                if (!this.visited.has(declaringMtd)) {
                    this.dvfgBuilder.buildForSingleMethod(declaringMtd);
                    this.visited.add(declaringMtd);
                }
                const returnStmts = declaringMtd.getReturnStmt();
                for (const stmt of returnStmts) {
                    const res = this.checkFromStmt(stmt, globalVarMap, checkAll, visited, depth + 1);
                    if (res) {
                        return true;
                    }
                }
            }

            // 当前语句的右值是函数参数赋值语句，查找所有调用处的入参情况
            const paramRef = this.isFromParameter(currentStmt);
            if (paramRef) {
                const paramIdx = paramRef.getIndex();
                const callsites = this.cg.getInvokeStmtByMethod(currentStmt.getCfg().getDeclaringMethod().getSignature());
                this.processCallsites(callsites);
                const argDefs = this.collectArgDefs(paramIdx, callsites);
                for (const stmt of argDefs) {
                    const res = this.checkFromStmt(stmt, globalVarMap, checkAll, visited, depth + 1);
                    if (res) {
                        return true;
                    }
                }
            }

            // 当前语句的右值是属性赋值语句，查找该属性的初始化语句
            if (currentStmt instanceof ArkAssignStmt && currentStmt.getRightOp() instanceof AbstractFieldRef) {
                const fieldSignature = (currentStmt.getRightOp() as AbstractFieldRef).getFieldSignature();
                const classSignature = fieldSignature.getDeclaringSignature();
                if (classSignature instanceof ClassSignature) {
                    const field = this.scene.getClass(classSignature)?.getField(fieldSignature);
                    if (field) {
                        field.getInitializer().forEach(s => worklist.push(this.dvfg.getOrNewDVFGNode(s)));
                    }
                }
            }

            // 当前语句是return语句，查找return操作数的相关语句
            if (currentStmt instanceof ArkReturnStmt) {
                const returnOp = currentStmt.getOp();
                if (returnOp instanceof Local) {
                    let checkStmt =
                        this.getLastAssignStmt(returnOp, stmt) ??
                        this.checkTargetLocalAsGlobal(currentStmt.getCfg().getDeclaringMethod(), stmt, returnOp, globalVarMap);
                    if (checkStmt !== null) {
                        worklist.push(this.dvfg.getOrNewDVFGNode(checkStmt));
                    }
                }
            }
            current.getIncomingEdge().forEach(e => worklist.push(e.getSrcNode() as DVFGNode));
        }
        return false;
    }

    private isRightOpGlobalVar(stmt: Stmt): Local | undefined {
        if (stmt instanceof ArkAssignStmt) {
            const rightOp = stmt.getRightOp();
            if (rightOp instanceof Local && !rightOp.getDeclaringStmt()) {
                return rightOp;
            }
        }
        return undefined;
    }

    private isLocalFromImport(local: Local, importInfos: ImportInfo[]): Local | undefined {
        for (const importInfo of importInfos) {
            if (importInfo.getImportClauseName() === local.getName()) {
                const exportInfo = importInfo.getLazyExportInfo();
                if (exportInfo === null) {
                    return undefined;
                }
                const arkExport = exportInfo.getArkExport();
                if (arkExport === null || arkExport === undefined) {
                    return undefined;
                }
                if (!(arkExport instanceof Local)) {
                    return undefined;
                }
                return arkExport;
            }
        }
        return undefined;
    }

    private processCallsites(callsites: Stmt[]): void {
        callsites.forEach(cs => {
            const declaringMtd = cs.getCfg().getDeclaringMethod();
            if (!this.visited.has(declaringMtd)) {
                this.dvfgBuilder.buildForSingleMethod(declaringMtd);
                this.visited.add(declaringMtd);
            }
        });
    }

    // 判断语句是否为赋值语句，且左值的定义来自于ArkTS1.2
    private isLeftOpOrReturnOpDefinedInStaticArkTS(stmt: Stmt): boolean {
        if (!(stmt instanceof ArkAssignStmt) && !(stmt instanceof ArkReturnStmt)) {
            return false;
        }
        let operand: Value;
        if (stmt instanceof ArkAssignStmt) {
            operand = stmt.getLeftOp();
        } else {
            operand = stmt.getOp();
        }
        if (!(operand instanceof Local)) {
            return false;
        }
        return this.isLocalDefinedInStaticArkTS(operand);
    }

    private isFromParameter(stmt: Stmt): ArkParameterRef | undefined {
        if (!(stmt instanceof ArkAssignStmt)) {
            return undefined;
        }
        const rightOp = stmt.getRightOp();
        if (rightOp instanceof ArkParameterRef) {
            return rightOp;
        }
        return undefined;
    }

    private collectArgDefs(argIdx: number, callsites: Stmt[]): Stmt[] {
        const getKey = (v: Value): Value | FieldSignature => {
            return v instanceof ArkInstanceFieldRef ? v.getFieldSignature() : v;
        };
        return callsites.flatMap(callsite => {
            const target: Value | FieldSignature = getKey(callsite.getInvokeExpr()!.getArg(argIdx));
            let refs = Array.from(this.dvfg.getOrNewDVFGNode(callsite).getIncomingEdge())
                .map(e => (e.getSrcNode() as DVFGNode).getStmt())
                .filter(s => {
                    return s instanceof ArkAssignStmt && target === getKey(s.getLeftOp());
                });
            // 以上步骤未找到defs语句，说明入参变量来源自import信息
            if (refs.length === 0 && target instanceof Local) {
                const importInfos = callsite.getCfg().getDeclaringMethod().getDeclaringArkFile().getImportInfos();
                const importValue = this.isLocalFromImport(target, importInfos);
                if (importValue && importValue.getDeclaringStmt() !== null) {
                    return importValue.getDeclaringStmt()!;
                }
            }
            return refs;
        });
    }

    private addIssueReport(stmt: Stmt, operand: Value, checkAll: boolean = true): void {
        const severity = this.rule.alert ?? this.metaData.severity;
        const warnInfo = this.getLineAndColumn(stmt, operand);
        const problem = 'builtin-api';
        let desc = `Builtin API is not support in ArkTS1.2 (${this.rule.ruleId.replace('@migration/', '')})`;
        if (!checkAll) {
            desc = `Can not check when function call chain depth exceeds ${CALL_DEPTH_LIMIT}, please check it manually (${this.rule.ruleId.replace('@migration/', '')})`;
        }

        let defects = new Defects(
            warnInfo.line,
            warnInfo.startCol,
            warnInfo.endCol,
            problem,
            desc,
            severity,
            this.rule.ruleId,
            warnInfo.filePath,
            this.metaData.ruleDocPath,
            true,
            false,
            false
        );
        this.issues.push(new IssueReport(defects, undefined));
    }

    private getLineAndColumn(stmt: Stmt, operand: Value): WarnInfo {
        const arkFile = stmt.getCfg().getDeclaringMethod().getDeclaringArkFile();
        const originPosition = stmt.getOperandOriginalPosition(operand);
        if (arkFile && originPosition) {
            const originPath = arkFile.getFilePath();
            const line = originPosition.getFirstLine();
            const startCol = originPosition.getFirstCol();
            const endCol = startCol;
            return { line, startCol, endCol, filePath: originPath };
        } else {
            logger.debug('ArkFile is null.');
        }
        return { line: -1, startCol: -1, endCol: -1, filePath: '' };
    }
}
