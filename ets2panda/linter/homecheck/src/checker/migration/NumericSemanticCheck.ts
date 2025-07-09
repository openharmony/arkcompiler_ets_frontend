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
    AbstractExpr,
    AbstractFieldRef,
    AbstractInvokeExpr,
    AbstractRef,
    AnyType,
    ArkAssignStmt,
    ArkField,
    ArkIfStmt,
    ArkInstanceFieldRef,
    ArkInvokeStmt,
    ArkMethod,
    ArkNormalBinopExpr,
    ArkParameterRef,
    ArkUnopExpr,
    ArrayType,
    CallGraph,
    ClassSignature,
    ClosureFieldRef,
    CONSTRUCTOR_NAME,
    DVFGBuilder,
    LexicalEnvType,
    Local,
    MethodSignature,
    NamespaceSignature,
    NormalBinaryOperator,
    NullType,
    Scene,
    Stmt,
    TEMP_LOCAL_PREFIX,
    Type,
    UnaryOperator,
    UndefinedType,
    UnionType,
    UnknownType,
    Value,
} from 'arkanalyzer/lib';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Defects, MatcherCallback, Rule, RuleFix, Utils } from '../../Index';
import { IssueReport } from '../../model/Defects';
import { DVFG, DVFGNode } from 'arkanalyzer/lib/VFG/DVFG';
import { CALL_DEPTH_LIMIT, getGlobalLocalsInDefaultMethod, getLineAndColumn, GlobalCallGraphHelper } from './Utils';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';
import { NullConstant, NumberConstant, UndefinedConstant } from 'arkanalyzer/lib/core/base/Constant';
import { AliasType, ArkArrayRef, ArkClass, ArkFile, ArkReturnStmt, AstTreeUtils, NumberType, UnclearReferenceType } from 'arkanalyzer';
import { FixUtils } from '../../utils/common/FixUtils';
import { Sdk } from 'arkanalyzer/lib/Config';
import fs from 'fs';
import path from 'path';
import { ModifierType } from 'arkanalyzer/lib/core/model/ArkBaseModel';
import { WarnInfo } from '../../utils/common/Utils';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'NumericSemanticCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
};

const OhosSdkName = 'ohosSdk';
const HmsSdkName = 'hmsSdk';
const Ets1DirName = 'ets1.1';
const Ets2DirName = 'ets1.2';

enum NumberCategory {
    int = 'integer',
    long = 'long',
}

enum RuleCategory {
    SDKIntType = 'sdk-api-num2int',
}

enum IssueReason {
    OnlyUsedAsIntLong = 'only-used-as-int-or-long',
    UsedWithOtherType = 'not-only-used-as-int-or-long',
    CannotFindAll = 'cannot-find-all',
    RelatedWithNonETS2 = 'related-with-non-ets2',
    Other = 'other',
}

interface RuleOptions {
    ets2Sdks?: Sdk[];
}

export class NumericSemanticCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];
    private scene: Scene;
    private ets2Sdks?: Sdk[];
    private ets2SdkScene?: Scene;
    private fileGlobalLocals: Map<string, Local> = new Map<string, Local>();
    private readonly intTypeName = 'int';
    private readonly longTypeName = 'long';
    private cg: CallGraph;
    private dvfg: DVFG;
    private dvfgBuilder: DVFGBuilder;
    private visited: Set<ArkMethod> = new Set();
    private callDepth = 0;
    private classFieldRes: Map<string, [IssueReason, NumberCategory]> = new Map<string, [IssueReason, NumberCategory]>();

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: undefined,
            callback: this.check,
        };
        return [matchBuildCb];
    }

    public check = (scene: Scene): void => {
        this.scene = scene;

        // 为ets2的SDK单独生成scene，用于sdk检查时进行匹配使用，单独scene可以避免与源码的scene进行干扰
        let ets2Sdks = (this.rule.option[0] as RuleOptions | undefined)?.ets2Sdks ?? this.getEts2SdksWithRelativePath();
        if (ets2Sdks && ets2Sdks.length > 0) {
            this.ets2Sdks = ets2Sdks;
            this.ets2SdkScene = Utils.generateSceneForEts2SDK(ets2Sdks);
        }

        this.cg = GlobalCallGraphHelper.getCGInstance(scene);

        this.dvfg = new DVFG(this.cg);
        this.dvfgBuilder = new DVFGBuilder(this.dvfg, scene);

        for (let arkFile of scene.getFiles()) {
            // 此规则仅对arkts1.2进行检查，仅对要将arkts1.1迁移到arkts1.2的文件进行number转int的检查和自动修复
            if (arkFile.getLanguage() !== Language.ARKTS1_2) {
                continue;
            }
            const defaultMethod = arkFile.getDefaultClass().getDefaultArkMethod();
            if (defaultMethod) {
                this.dvfgBuilder.buildForSingleMethod(defaultMethod);
                this.fileGlobalLocals = getGlobalLocalsInDefaultMethod(defaultMethod);
            }
            for (let clazz of arkFile.getClasses()) {
                this.processClass(clazz);
            }
            for (let namespace of arkFile.getAllNamespacesUnderThisFile()) {
                for (let clazz of namespace.getClasses()) {
                    this.processClass(clazz);
                }
            }
        }
    };

    private getEts2SdksWithRelativePath(): Sdk[] | null {
        const ets1OhosSdk = this.scene.getProjectSdkMap().get(OhosSdkName);
        const ets1HmsSdk = this.scene.getProjectSdkMap().get(HmsSdkName);
        let sdks: Sdk[] = [];
        if (ets1OhosSdk !== undefined) {
            const sdkPath = ets1OhosSdk.path;
            if (sdkPath.includes(Ets1DirName)) {
                const ets2SdkPath = sdkPath.replace(Ets1DirName, Ets2DirName);
                if (fs.existsSync(ets2SdkPath)) {
                    sdks.push({ name: OhosSdkName, path: ets2SdkPath, moduleName: ets1OhosSdk.moduleName });
                }
            }
        }
        if (ets1HmsSdk !== undefined) {
            const sdkPath = ets1HmsSdk.path;
            if (sdkPath.includes(Ets1DirName)) {
                const ets2SdkPath = sdkPath.replace(Ets1DirName, Ets2DirName);
                if (fs.existsSync(ets2SdkPath)) {
                    sdks.push({ name: HmsSdkName, path: ets2SdkPath, moduleName: ets1HmsSdk.moduleName });
                }
            }
        }
        if (sdks.length > 0) {
            return sdks;
        }
        return null;
    }

    public processClass(arkClass: ArkClass): void {
        this.classFieldRes = new Map<string, [IssueReason, NumberCategory]>();
        // 查找全部method，包含constructor、%instInit，%statInit等
        for (let mtd of arkClass.getMethods(true)) {
            this.processArkMethod(mtd);
        }
    }

    public processArkMethod(target: ArkMethod): void {
        const stmts = target.getBody()?.getCfg().getStmts() ?? [];
        // 场景1：需要检查的sdk调用语句，该stmt为sink点
        for (const stmt of stmts) {
            try {
                this.checkSdkArgsInStmt(stmt);
            } catch (e) {
                logger.error(`Error when check sdk called in stmt: ${stmt.toString()}, method: ${target.getSignature().toString()}, error: ${e}`);
            }
        }
    }

    private checkSdkArgsInStmt(stmt: Stmt): void {
        // res用于存放检查过程中所有找到的Local变量，记录这些变量是否均仅当做int使用，若是则可以设置成int类型，跨函数场景下可能包含其他method中的Local变量
        const res = new Map<Local, [IssueReason, NumberCategory]>();
        this.callDepth = 0;
        const intArgs = this.getSDKIntLongArgs(stmt);
        if (intArgs === null || intArgs.size === 0) {
            return;
        }

        for (const [arg, category] of intArgs) {
            const issueReason = this.checkValueOnlyUsedAsIntLong(stmt, arg, res, category);
            if (issueReason !== IssueReason.OnlyUsedAsIntLong) {
                this.addIssueReport(RuleCategory.SDKIntType, category, issueReason, true, stmt, arg);
            }
        }
        res.forEach(([issueReason, numberCategory], local) => {
            if (local.getName().startsWith(TEMP_LOCAL_PREFIX)) {
                if (issueReason === IssueReason.OnlyUsedAsIntLong) {
                    this.addIssueReportOnClassField(local, RuleCategory.SDKIntType, numberCategory, stmt);
                }
                return;
            }
            const declaringStmt = local.getDeclaringStmt();
            if (declaringStmt !== null && issueReason === IssueReason.OnlyUsedAsIntLong) {
                this.addIssueReport(RuleCategory.SDKIntType, numberCategory, issueReason, true, declaringStmt, local, undefined, stmt);
            }
        });
    }

    private addIssueReportOnClassField(local: Local, ruleCategory: RuleCategory, numberCategory: NumberCategory, usedStmt: Stmt): void {
        const declaringStmt = local.getDeclaringStmt();
        if (!declaringStmt || !(declaringStmt instanceof ArkAssignStmt)) {
            return;
        }
        const rightOp = declaringStmt.getRightOp();
        if (!(rightOp instanceof AbstractFieldRef)) {
            return;
        }
        const declaringSig = rightOp.getFieldSignature().getDeclaringSignature();
        if (declaringSig instanceof NamespaceSignature) {
            return;
        }
        if (declaringSig.toString() !== declaringStmt.getCfg().getDeclaringMethod().getDeclaringArkClass().getSignature().toString()) {
            return;
        }
        const declaringClass = this.scene.getClass(declaringSig);
        if (declaringClass === null) {
            return;
        }
        const field = declaringClass.getField(rightOp.getFieldSignature());
        if (field === null) {
            return;
        }
        this.addIssueReport(ruleCategory, numberCategory, IssueReason.OnlyUsedAsIntLong, true, undefined, undefined, field, usedStmt);
    }

    private isMethodFromSDK(method: ArkMethod): boolean {
        const projectName = method.getDeclaringArkFile().getProjectName();
        return projectName === OhosSdkName || projectName === HmsSdkName;
    }

    // 语句为sdk的调用且形参有int或long类型，找出所有int类型形参的实参
    private getSDKIntLongArgs(stmt: Stmt): Map<Value, NumberCategory> | null {
        let invokeExpr: AbstractInvokeExpr;
        if (stmt instanceof ArkAssignStmt) {
            const rightOp = stmt.getRightOp();
            if (rightOp instanceof AbstractInvokeExpr) {
                invokeExpr = rightOp;
            } else {
                return null;
            }
        } else if (stmt instanceof ArkInvokeStmt) {
            invokeExpr = stmt.getInvokeExpr();
        } else {
            return null;
        }
        const callMethod = this.scene.getMethod(invokeExpr.getMethodSignature());
        if (callMethod === null || !this.isMethodFromSDK(callMethod)) {
            return null;
        }

        const args = invokeExpr.getArgs();
        let containNumberArg = false;
        for (const arg of args) {
            if (arg instanceof Local || arg instanceof NumberConstant) {
                const argType = arg.getType();
                if (this.isTypeWithNumberType(argType) || argType instanceof AnyType) {
                    containNumberArg = true;
                    break;
                }
                if (argType instanceof UnionType && this.containsType(argType.getTypes(), NumberType.getInstance())) {
                    containNumberArg = true;
                    break;
                }
            }
        }
        if (!containNumberArg) {
            return null;
        }

        const res: Map<Value, NumberCategory> = new Map<Value, NumberCategory>();
        // 根据找到的对应arkts1.1中的SDK接口匹配到对应在arkts1.2中的SDK接口
        const Ets2SdkSignature = this.getEts2SdkSignatureWithEts1Method(callMethod, args);
        if (Ets2SdkSignature === null) {
            return null;
        }
        Ets2SdkSignature.getMethodSubSignature()
            .getParameters()
            .forEach((param, index) => {
                if (this.isIntType(param.getType())) {
                    res.set(args[index], NumberCategory.int);
                } else if (this.isLongType(param.getType())) {
                    res.set(args[index], NumberCategory.long);
                }
            });
        if (res.size === 0) {
            return null;
        }
        return res;
    }

    private getMatchedSignature(ets1SDK: ArkMethod, args: Value[]): MethodSignature | null {
        const declareSigs = ets1SDK.getDeclareSignatures();
        if (declareSigs === null) {
            return null;
        }
        if (declareSigs.length === 1) {
            return declareSigs[0];
        }

        let ets1SigMatched: MethodSignature | null = null;
        for (const sig of declareSigs) {
            const params = sig.getMethodSubSignature().getParameters();
            let matched = true;
            for (let i = 0; i < args.length; i++) {
                const argType = args[i].getType();
                const paramType = params[i].getType();
                if (argType === paramType) {
                    continue;
                }
                if (argType instanceof AnyType) {
                    continue;
                }
                if (!(argType instanceof UnionType) || !this.containsType(argType.getTypes(), paramType)) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                ets1SigMatched = sig;
                break;
            }
        }
        return ets1SigMatched;
    }

    private containsType(types: Type[], targetType: Type): boolean {
        for (const t of types) {
            if (t === targetType) {
                return true;
            }
        }
        return false;
    }

    private matchEts1NumberEts2IntLongMethodSig(ets2Sigs: MethodSignature[], ets1Sig: MethodSignature): MethodSignature | null {
        let intSDKMatched: MethodSignature | null = null;
        const ets1Params = ets1Sig.getMethodSubSignature().getParameters();
        for (const ets2Sig of ets2Sigs) {
            let isInt = false;
            let isLong = false;
            const ets2Params = ets2Sig.getMethodSubSignature().getParameters();
            if (ets2Params.length !== ets1Params.length) {
                continue;
            }
            for (let i = 0; i < ets1Params.length; i++) {
                const ets2ParamType = ets2Params[i].getType();
                const ets1ParamType = ets1Params[i].getType();
                if (ets2ParamType === ets1ParamType) {
                    continue;
                }
                if (this.isIntType(ets2ParamType) && ets1ParamType instanceof NumberType) {
                    isInt = true;
                    continue;
                }
                if (this.isLongType(ets2ParamType) && ets1ParamType instanceof NumberType) {
                    isLong = true;
                    continue;
                }
                isInt = false;
                isLong = false;
            }
            if (isLong) {
                return ets2Sig;
            }
            if (isInt) {
                intSDKMatched = ets2Sig;
            }
        }
        return intSDKMatched;
    }

    private getEts2SdkSignatureWithEts1Method(ets1SDK: ArkMethod, args: Value[], exactMatch: boolean = true): MethodSignature | null {
        const ets2Sdks = this.ets2Sdks;
        if (ets2Sdks === undefined || ets2Sdks.length === 0) {
            return null;
        }

        const ets1SigMatched = this.getMatchedSignature(ets1SDK, args);
        if (ets1SigMatched === null) {
            return null;
        }

        const ets1SdkFileName = ets1SDK.getDeclaringArkFile().getName();
        const ets2SdkFiles = this.ets2SdkScene?.getSdkArkFiles().filter(f => {
            for (const sdk of ets2Sdks) {
                if (fs.existsSync(path.join(sdk.path, ets1SdkFileName)) && f.getName() === ets1SdkFileName) {
                    return true;
                }
                const newEts2SdkFileName = ets1SdkFileName.replace('.d.ts', '.d.ets');
                if (fs.existsSync(path.join(sdk.path, newEts2SdkFileName)) && f.getName() === newEts2SdkFileName) {
                    return true;
                }
            }
            return false;
        });
        if (ets2SdkFiles === undefined || ets2SdkFiles.length === 0) {
            return null;
        }

        for (const file of ets2SdkFiles) {
            const ets2SdkMethod = this.getEts2SdkWithEts1SdkInfo(file, ets1SDK);
            if (!ets2SdkMethod) {
                continue;
            }
            const declareSigs = ets2SdkMethod.getDeclareSignatures();
            if (declareSigs === null) {
                return null;
            }
            if (!exactMatch && declareSigs.length === 1) {
                return declareSigs[0];
            }
            return this.matchEts1NumberEts2IntLongMethodSig(declareSigs, ets1SigMatched);
        }
        return null;
    }

    private getEts2SdkWithEts1SdkInfo(ets2File: ArkFile, ets1SDK: ArkMethod): ArkMethod | null {
        const ets1Class = ets1SDK.getDeclaringArkClass();
        const ets1Namespace = ets1Class.getDeclaringArkNamespace();
        if (ets1Namespace === undefined) {
            return ets2File.getClassWithName(ets1Class.getName())?.getMethodWithName(ets1SDK.getName()) ?? null;
        }
        return ets2File.getNamespaceWithName(ets1Namespace.getName())?.getClassWithName(ets1Class.getName())?.getMethodWithName(ets1SDK.getName()) ?? null;
    }

    // 判断类型是否为int，当前ArkAnalyzer对于int的表示应该是name为int的AliasType或UnclearReferenceType
    private isIntType(checkType: Type): boolean {
        if (checkType instanceof AliasType || checkType instanceof UnclearReferenceType) {
            if (checkType.getName() === this.intTypeName) {
                return true;
            }
        }
        return false;
    }

    // 判断类型是否为ilong，当前ArkAnalyzer对于long的表示应该是name为long的AliasType或UnclearReferenceType
    private isLongType(checkType: Type): boolean {
        if (checkType instanceof AliasType || checkType instanceof UnclearReferenceType) {
            if (checkType.getName() === this.longTypeName) {
                return true;
            }
        }
        return false;
    }

    // 此处value作为函数入参、数组下标、a/b，因为三地址码原则的限制，只可能是Local和NumberConstant类型，其他value的类型均不可能存在
    private checkValueOnlyUsedAsIntLong(
        stmt: Stmt,
        value: Value,
        hasChecked: Map<Local, [IssueReason, NumberCategory]>,
        numberCategory: NumberCategory
    ): IssueReason {
        if (stmt.getCfg().getDeclaringMethod().getLanguage() !== Language.ARKTS1_2) {
            return IssueReason.RelatedWithNonETS2;
        }
        if (value instanceof NumberConstant) {
            if (this.isNumberConstantWithDecimalPoint(value)) {
                return IssueReason.UsedWithOtherType;
            }
            return IssueReason.OnlyUsedAsIntLong;
        }
        if (value instanceof UndefinedConstant || value instanceof NullConstant) {
            // 对于用null或undefined赋值的场景，认为未进行初始化，还需其他赋值语句进行检查
            return IssueReason.OnlyUsedAsIntLong;
        }
        if (value instanceof Local) {
            return this.isLocalOnlyUsedAsIntLong(stmt, value, hasChecked, numberCategory);
        }
        if (value instanceof AbstractExpr) {
            return this.isAbstractExprOnlyUsedAsIntLong(stmt, value, hasChecked, numberCategory);
        }
        if (value instanceof AbstractRef) {
            return this.isAbstractRefOnlyUsedAsIntLong(stmt, value, hasChecked, numberCategory);
        }
        logger.error(`Need to handle new value type: ${value.getType().getTypeString()}`);
        return IssueReason.Other;
    }

    private isNumberConstantWithDecimalPoint(constant: NumberConstant): boolean {
        return constant.getValue().includes('.');
    }

    private isTypeWithNumberType(localType: Type): boolean {
        if (localType instanceof NumberType) {
            return true;
        }
        if (localType instanceof UnionType) {
            for (const t of localType.getTypes()) {
                if (t instanceof NumberType || t instanceof UndefinedType || t instanceof NullType) {
                    continue;
                }
                return false;
            }
            return true;
        }
        return false;
    }

    private isLocalOnlyUsedAsIntLong(
        stmt: Stmt,
        local: Local,
        hasChecked: Map<Local, [IssueReason, NumberCategory]>,
        numberCategory: NumberCategory
    ): IssueReason {
        // hasChecked map中已有此local，若原先为int，现在为long则使用long替换，其余情况不改动，直接返回，避免死循环
        const currentInfo = hasChecked.get(local);
        if (currentInfo) {
            if (currentInfo[1] === NumberCategory.int && numberCategory === NumberCategory.long) {
                hasChecked.set(local, [IssueReason.OnlyUsedAsIntLong, NumberCategory.long]);
            }
            return IssueReason.OnlyUsedAsIntLong;
        }
        // 先将value加入map中，默认设置成false，避免后续递归查找阶段出现死循环，最后再根据查找结果绝对是否重新设置成true
        hasChecked.set(local, [IssueReason.Other, numberCategory]);

        // 正常情况不会走到此分支，除非类型为any、联合类型等复杂类型，保守处理返回false，不转int
        // 对于联合类型仅包含number和null、undefined，可以认为是OK的
        const localType = local.getType();
        if (!this.isTypeWithNumberType(localType)) {
            if (localType instanceof UnknownType) {
                hasChecked.set(local, [IssueReason.CannotFindAll, numberCategory]);
                return IssueReason.CannotFindAll;
            }
            logger.error(`Local type is not number, local: ${local.getName()}, local type: ${local.getType().getTypeString()}`);
            hasChecked.set(local, [IssueReason.UsedWithOtherType, numberCategory]);
            return IssueReason.UsedWithOtherType;
        }

        let checkStmts: Stmt[] = [];
        const declaringStmt = local.getDeclaringStmt();
        if (declaringStmt === null) {
            // 无定义语句的local可能来自于import，需要根据import信息查找其原始local
            const newLocal = this.getLocalFromGlobal(local) ?? this.getLocalFromImportInfo(local, hasChecked, numberCategory);
            if (newLocal === null) {
                // local非来自于import，确实是缺少定义语句，或者是从非1.2文件import，直接返回false，因为就算是能确认local仅当做int使用，也找不到定义语句去修改类型注解为int，所以后续检查都没有意义
                logger.error(`Missing declaring stmt, local: ${local.getName()}`);
                return hasChecked.get(local)![0];
            }
            const declaringStmt = newLocal.getDeclaringStmt();
            if (declaringStmt === null) {
                // local变量未找到定义语句，直接返回false，因为就算是能确认local仅当做int使用，也找不到定义语句去修改类型注解为int，所以后续检查都没有意义
                logger.error(`Missing declaring stmt, local: ${local.getName()}`);
                hasChecked.set(local, [IssueReason.Other, numberCategory]);
                return IssueReason.Other;
            }
            hasChecked.delete(local);
            return this.isLocalOnlyUsedAsIntLong(declaringStmt, newLocal, hasChecked, numberCategory);
        }
        checkStmts.push(declaringStmt);
        local.getUsedStmts().forEach(s => {
            if (s !== stmt) {
                checkStmts.push(s);
            }
        });
        // usedStmts中不会记录local为leftOp的stmt，此处需要补充
        declaringStmt
            .getCfg()
            .getStmts()
            .forEach(s => {
                if (s === declaringStmt || !(s instanceof ArkAssignStmt) || s.getLeftOp() !== local) {
                    return;
                }
                checkStmts.push(s);
            });

        for (const s of checkStmts) {
            if (s instanceof ArkAssignStmt && s.getLeftOp() === local) {
                const checkRightOp = this.checkValueOnlyUsedAsIntLong(s, s.getRightOp(), hasChecked, numberCategory);
                if (checkRightOp !== IssueReason.OnlyUsedAsIntLong) {
                    return checkRightOp;
                }
                continue;
            }
            // 当前检查的local位于赋值语句的右边，若参与除法运算则看做double类型使用，若作为SDK入参依据SDK定义，其余运算、赋值等处理不会影响其自身从int -> number，所以不处理
            if (s instanceof ArkAssignStmt && s.getLeftOp() !== local) {
                const rightOp = s.getRightOp();
                if (rightOp instanceof ArkNormalBinopExpr && rightOp.getOperator() === NormalBinaryOperator.Division) {
                    hasChecked.set(local, [IssueReason.UsedWithOtherType, numberCategory]);
                    return IssueReason.UsedWithOtherType;
                }
                if (rightOp instanceof AbstractInvokeExpr) {
                    const res = this.checkLocalUsedAsSDKArg(rightOp, local, hasChecked);
                    if (res === null) {
                        continue;
                    }
                    hasChecked.set(local, res);
                    return res[0];
                }
                continue;
            }
            if (s instanceof ArkInvokeStmt) {
                // 函数调用语句，local作为实参或base，除作为SDK入参之外，其余场景不会影响其值的变化，不会导致int被重新赋值为number使用
                const res = this.checkLocalUsedAsSDKArg(s.getInvokeExpr(), local, hasChecked);
                if (res === null) {
                    continue;
                }
                hasChecked.set(local, res);
                return res[0];
            }
            if (s instanceof ArkReturnStmt) {
                // return语句，local作为返回值，不会影响其值的变化，不会导致int被重新赋值为number使用
                continue;
            }
            if (s instanceof ArkIfStmt) {
                // 条件判断语句，local作为condition expr的op1或op2，进行二元条件判断，不会影响其值的变化，不会导致int被重新赋值为number使用
                continue;
            }
            logger.error(`Need to check new type of stmt: ${s.toString()}, method: ${s.getCfg().getDeclaringMethod().getSignature().toString()}`);
            return IssueReason.Other;
        }
        hasChecked.set(local, [IssueReason.OnlyUsedAsIntLong, numberCategory]);
        return IssueReason.OnlyUsedAsIntLong;
    }

    // 判断local是否是SDK invoke expr的入参，且其类型是int或long，否则返回null
    private checkLocalUsedAsSDKArg(
        expr: AbstractInvokeExpr,
        local: Local,
        hasChecked: Map<Local, [IssueReason, NumberCategory]>
    ): [IssueReason, NumberCategory] | null {
        const method = this.scene.getMethod(expr.getMethodSignature());
        if (method === null) {
            logger.error(`Failed to find method: ${expr.getMethodSignature().toString()}`);
            return null;
        }
        const args = expr.getArgs();
        if (this.isMethodFromSDK(method)) {
            const ets2SDKSig = this.getEts2SdkSignatureWithEts1Method(method, args, true);
            if (ets2SDKSig === null) {
                return null;
            }
            const argIndex = expr.getArgs().indexOf(local);
            if (argIndex < 0 || argIndex >= expr.getArgs().length) {
                return null;
            }
            const params = ets2SDKSig.getMethodSubSignature().getParameters();
            const currLocal = hasChecked.get(local);
            if (this.isIntType(params[argIndex].getType())) {
                if (currLocal === undefined) {
                    return [IssueReason.OnlyUsedAsIntLong, NumberCategory.int];
                }
                if (currLocal[1] === NumberCategory.long) {
                    return [IssueReason.OnlyUsedAsIntLong, NumberCategory.long];
                }
                return [IssueReason.OnlyUsedAsIntLong, NumberCategory.int];
            }
            if (this.isLongType(params[argIndex].getType())) {
                return [IssueReason.OnlyUsedAsIntLong, NumberCategory.long];
            }
        }
        return null;
    }

    private getLocalFromGlobal(local: Local): Local | null {
        const globalLocal = this.fileGlobalLocals.get(local.getName());
        if (globalLocal === undefined) {
            return null;
        }
        return globalLocal;
    }

    private getLocalFromImportInfo(local: Local, hasChecked: Map<Local, [IssueReason, NumberCategory]>, numberCategory: NumberCategory): Local | null {
        const usedStmts = local.getUsedStmts();
        if (usedStmts.length < 1) {
            return null;
        }
        const importInfo = usedStmts[0].getCfg().getDeclaringMethod().getDeclaringArkFile().getImportInfoBy(local.getName());
        if (importInfo === undefined) {
            return null;
        }
        const exportInfo = importInfo.getLazyExportInfo();
        if (exportInfo === null) {
            return null;
        }
        if (exportInfo.getLanguage() !== Language.ARKTS1_2) {
            hasChecked.set(local, [IssueReason.RelatedWithNonETS2, numberCategory]);
            return null;
        }
        const exportLocal = importInfo.getLazyExportInfo()?.getArkExport();
        if (exportLocal === null || exportLocal === undefined) {
            return null;
        }
        if (exportLocal instanceof Local) {
            return exportLocal;
        }
        return null;
    }

    private isAbstractExprOnlyUsedAsIntLong(
        stmt: Stmt,
        expr: AbstractExpr,
        hasChecked: Map<Local, [IssueReason, NumberCategory]>,
        numberCategory: NumberCategory
    ): IssueReason {
        if (expr instanceof ArkNormalBinopExpr) {
            if (expr.getOperator() === NormalBinaryOperator.Division) {
                return IssueReason.UsedWithOtherType;
            }
            const isOp1Int = this.checkValueOnlyUsedAsIntLong(stmt, expr.getOp1(), hasChecked, numberCategory);
            const isOp2Int = this.checkValueOnlyUsedAsIntLong(stmt, expr.getOp2(), hasChecked, numberCategory);
            if (isOp1Int === IssueReason.OnlyUsedAsIntLong && isOp2Int === IssueReason.OnlyUsedAsIntLong) {
                return IssueReason.OnlyUsedAsIntLong;
            }
            if (isOp1Int === IssueReason.UsedWithOtherType || isOp2Int === IssueReason.UsedWithOtherType) {
                return IssueReason.UsedWithOtherType;
            }
            if (isOp1Int === IssueReason.RelatedWithNonETS2 || isOp2Int === IssueReason.RelatedWithNonETS2) {
                return IssueReason.RelatedWithNonETS2;
            }
            if (isOp1Int === IssueReason.CannotFindAll || isOp2Int === IssueReason.CannotFindAll) {
                return IssueReason.CannotFindAll;
            }
            return IssueReason.Other;
        }
        if (expr instanceof AbstractInvokeExpr) {
            const method = this.scene.getMethod(expr.getMethodSignature());
            if (method === null) {
                logger.error(`Failed to find method: ${expr.getMethodSignature().toString()}`);
                return IssueReason.Other;
            }
            if (this.isMethodFromSDK(method)) {
                const ets2SDKSig = this.getEts2SdkSignatureWithEts1Method(method, expr.getArgs(), false);
                if (ets2SDKSig === null) {
                    return IssueReason.RelatedWithNonETS2;
                }
                if (this.isIntType(ets2SDKSig.getType()) || this.isLongType(ets2SDKSig.getType())) {
                    return IssueReason.OnlyUsedAsIntLong;
                }
                return IssueReason.UsedWithOtherType;
            }
            if (method.getLanguage() !== Language.ARKTS1_2) {
                return IssueReason.RelatedWithNonETS2;
            }
            const returnStmt = method.getReturnStmt();
            for (const s of returnStmt) {
                if (!(s instanceof ArkReturnStmt)) {
                    continue;
                }
                const res = this.checkValueOnlyUsedAsIntLong(s, s.getOp(), hasChecked, numberCategory);
                if (res !== IssueReason.OnlyUsedAsIntLong) {
                    return res;
                }
            }
            return IssueReason.OnlyUsedAsIntLong;
        }
        if (expr instanceof ArkUnopExpr) {
            if (expr.getOperator() === UnaryOperator.Neg || expr.getOperator() === UnaryOperator.BitwiseNot) {
                return this.checkValueOnlyUsedAsIntLong(stmt, expr.getOp(), hasChecked, numberCategory);
            }
            logger.error(`Need to handle new type of unary operator: ${expr.getOperator().toString()}`);
            return IssueReason.Other;
        }
        // 剩余的expr的类型不应该出现在这里，如果出现了表示有场景未考虑到，打印日志记录，进行补充
        logger.error(`Need to handle new type of expr: ${expr.toString()}`);
        return IssueReason.Other;
    }

    private isAbstractRefOnlyUsedAsIntLong(
        stmt: Stmt,
        ref: AbstractRef,
        hasChecked: Map<Local, [IssueReason, NumberCategory]>,
        numberCategory: NumberCategory
    ): IssueReason {
        if (ref instanceof ArkArrayRef) {
            // 使用数组中某元素进行赋值的场景很复杂，需要判断index的具体值，需要判断数组中的队应元素的全部使用场景，当前不做检查，直接返回false
            return IssueReason.CannotFindAll;
        }
        if (ref instanceof AbstractFieldRef) {
            return this.checkFieldRef(ref, stmt.getCfg().getDeclaringMethod().getDeclaringArkClass().getSignature(), numberCategory);
        }
        if (ref instanceof ArkParameterRef) {
            return this.checkAllArgsOfParameter(stmt, hasChecked, numberCategory);
        }
        if (ref instanceof ClosureFieldRef) {
            return this.checkClosureFieldRef(ref, hasChecked, numberCategory);
        }
        // 其他ref类型经分析不应该出现在此处，若存在输出日志，通过分析日志信息进行补充处理，包括：ArkCaughtExceptionRef, GlobalRef, ArkThisRef
        logger.error(`Need to check new type of ref in stmt: ${stmt.toString()}`);
        return IssueReason.Other;
    }

    private checkFieldRef(ref: AbstractRef, currentClassSig: ClassSignature, numberCategory: NumberCategory): IssueReason {
        const refType = ref.getType();
        if (!(ref instanceof AbstractFieldRef)) {
            if (!this.isTypeWithNumberType(refType)) {
                if (refType instanceof UnknownType) {
                    return IssueReason.CannotFindAll;
                }
                return IssueReason.UsedWithOtherType;
            }
            // 此处若想充分解析，需要在整个项目中找到该field的所有使用到的地方，效率很低，且很容易找漏，当前不做检查，直接返回false
            return IssueReason.CannotFindAll;
        }
        const fieldBase = ref.getFieldSignature().getDeclaringSignature();
        if (fieldBase instanceof NamespaceSignature) {
            return IssueReason.CannotFindAll;
        }
        const baseClass = this.scene.getClass(fieldBase);
        if (baseClass === null) {
            return IssueReason.CannotFindAll;
        }
        if (baseClass.getLanguage() !== Language.ARKTS1_2) {
            return IssueReason.RelatedWithNonETS2;
        }
        if (baseClass.getSignature().toString() !== currentClassSig.toString()) {
            return IssueReason.CannotFindAll;
        }
        const field = baseClass.getField(ref.getFieldSignature());
        if (field === null) {
            return IssueReason.CannotFindAll;
        }
        const fieldName = field.getName();
        const existRes = this.classFieldRes.get(fieldName);
        if (existRes !== undefined) {
            return existRes[0];
        }
        if (!this.isTypeWithNumberType(refType)) {
            if (refType instanceof UnknownType) {
                const res = IssueReason.CannotFindAll;
                this.classFieldRes.set(fieldName, [res, numberCategory]);
                return res;
            }
            const res = IssueReason.UsedWithOtherType;
            this.classFieldRes.set(fieldName, [res, numberCategory]);
            return res;
        }
        if (field.containsModifier(ModifierType.READONLY)) {
            // 先写入默认值，避免后续查找时出现死循环，得到结果后再进行替换
            this.classFieldRes.set(fieldName, [IssueReason.OnlyUsedAsIntLong, numberCategory]);
            const res = this.checkReadonlyFieldInitializer(field, baseClass, numberCategory);
            this.classFieldRes.set(fieldName, [res, numberCategory]);
            return res;
        }
        if (field.containsModifier(ModifierType.PRIVATE)) {
            this.classFieldRes.set(fieldName, [IssueReason.OnlyUsedAsIntLong, numberCategory]);
            const res = this.checkPrivateField(field, baseClass, numberCategory);
            this.classFieldRes.set(fieldName, [res, numberCategory]);
            return res;
        }
        // 此处若想充分解析，需要在整个项目中找到该field的所有使用到的地方，效率很低，且很容易找漏，当前不做检查，直接返回false
        const res = IssueReason.CannotFindAll;
        this.classFieldRes.set(fieldName, [res, numberCategory]);
        return res;
    }

    private checkReadonlyFieldInitializer(field: ArkField, baseClass: ArkClass, numberCategory: NumberCategory): IssueReason {
        const constructorMethod = baseClass.getMethodWithName(CONSTRUCTOR_NAME);
        if (constructorMethod === null) {
            return IssueReason.CannotFindAll;
        }
        const res =
            this.checkReadonlyFieldInitInMethod(field, constructorMethod, numberCategory) ??
            this.checkReadonlyFieldInitInMethod(field, baseClass.getStaticInitMethod(), numberCategory) ??
            this.checkReadonlyFieldInitInMethod(field, baseClass.getInstanceInitMethod(), numberCategory);

        if (res === null) {
            return IssueReason.CannotFindAll;
        }
        return res;
    }

    private checkReadonlyFieldInitInMethod(field: ArkField, method: ArkMethod, numberCategory: NumberCategory): IssueReason | null {
        const stmts = method.getCfg()?.getStmts();
        if (stmts === undefined) {
            return null;
        }
        for (const stmt of stmts) {
            if (!(stmt instanceof ArkAssignStmt)) {
                continue;
            }
            const leftOp = stmt.getLeftOp();
            if (!(leftOp instanceof AbstractFieldRef)) {
                continue;
            }
            if (leftOp.getFieldName() === field.getName()) {
                return this.checkValueOnlyUsedAsIntLong(stmt, stmt.getRightOp(), new Map<Local, [IssueReason, NumberCategory]>(), numberCategory);
            }
        }
        return null;
    }

    private checkPrivateField(field: ArkField, baseClass: ArkClass, numberCategory: NumberCategory): IssueReason {
        if (this.fieldWithSetter(field, baseClass)) {
            return IssueReason.CannotFindAll;
        }
        const methods = baseClass.getMethods(true);
        for (const method of methods) {
            if (method.getName().startsWith('Set-') || method.getName().startsWith('Get-')) {
                continue;
            }
            const stmts = method.getCfg()?.getStmts();
            if (stmts === undefined) {
                continue;
            }
            for (const stmt of stmts) {
                const res = this.checkFieldUsedInStmt(field, stmt, numberCategory);
                if (res === null) {
                    continue;
                }
                if (res !== IssueReason.OnlyUsedAsIntLong) {
                    return res;
                }
            }
        }
        return IssueReason.OnlyUsedAsIntLong;
    }

    // 当前仅查找当前field的fieldRef在左边与fieldRef在右边的场景，其余均不检查，认为cannot find all
    private checkFieldUsedInStmt(field: ArkField, stmt: Stmt, numberCategory: NumberCategory): IssueReason | null {
        if (stmt instanceof ArkAssignStmt) {
            const leftOp = stmt.getLeftOp();
            const rightOp = stmt.getRightOp();
            if (leftOp instanceof AbstractFieldRef) {
                if (this.isFieldRefMatchArkField(leftOp, field)) {
                    return this.checkValueOnlyUsedAsIntLong(stmt, rightOp, new Map<Local, [IssueReason, NumberCategory]>(), numberCategory);
                }
                return null;
            }
            if (rightOp instanceof AbstractFieldRef) {
                if (this.isFieldRefMatchArkField(rightOp, field)) {
                    if (leftOp instanceof Local && leftOp.getName().startsWith(TEMP_LOCAL_PREFIX)) {
                        return this.checkTempLocalAssignByFieldRef(leftOp);
                    }
                    return IssueReason.OnlyUsedAsIntLong;
                }
                return null;
            }
        }
        const usedFieldRef = stmt.getFieldRef();
        if (usedFieldRef === undefined) {
            return null;
        }
        if (this.isFieldRefMatchArkField(usedFieldRef, field)) {
            return IssueReason.CannotFindAll;
        }
        return null;
    }

    // 此处只判断临时变量是否作为1.2 SDK的入参使用，且该参数的类型为int，则返回Used as int，其他情况均返回cannot find all
    private checkTempLocalAssignByFieldRef(tempLocal: Local): IssueReason {
        // fieldRef赋值的临时变量，应该有且只有1处usedStmt
        const usedStmts = tempLocal.getUsedStmts();
        if (usedStmts.length !== 1) {
            return IssueReason.CannotFindAll;
        }
        const usedStmt = usedStmts[0];
        if (usedStmt instanceof ArkInvokeStmt) {
            return this.checkFieldRefUsedInSDKArgs(tempLocal, usedStmt.getInvokeExpr());
        }
        if (usedStmt instanceof ArkAssignStmt) {
            const rightOp = usedStmt.getRightOp();
            if (rightOp instanceof AbstractInvokeExpr) {
                return this.checkFieldRefUsedInSDKArgs(tempLocal, rightOp);
            }
            return IssueReason.CannotFindAll;
        }
        return IssueReason.CannotFindAll;
    }

    private checkFieldRefUsedInSDKArgs(tempLocal: Local, invokeExpr: AbstractInvokeExpr): IssueReason {
        const method = this.scene.getMethod(invokeExpr.getMethodSignature());
        if (method === null) {
            return IssueReason.CannotFindAll;
        }
        const argIndex = invokeExpr.getArgs().indexOf(tempLocal);
        if (argIndex < 0 || argIndex >= invokeExpr.getArgs().length) {
            return IssueReason.CannotFindAll;
        }
        if (this.isMethodFromSDK(method)) {
            const ets2SDKSig = this.getEts2SdkSignatureWithEts1Method(method, invokeExpr.getArgs());
            if (ets2SDKSig) {
                const paramType = ets2SDKSig.getMethodSubSignature().getParameters()[argIndex].getType();
                if (this.isIntType(paramType) || this.isLongType(paramType)) {
                    return IssueReason.OnlyUsedAsIntLong;
                }
            }
        }
        return IssueReason.CannotFindAll;
    }

    private isFieldRefMatchArkField(fieldRef: AbstractFieldRef, field: ArkField): boolean {
        const refDeclaringSig = fieldRef.getFieldSignature().getDeclaringSignature();
        if (refDeclaringSig instanceof NamespaceSignature) {
            return false;
        }
        if (refDeclaringSig.toString() !== field.getDeclaringArkClass().getSignature().toString()) {
            return false;
        }
        return fieldRef.getFieldName() === field.getName();
    }

    private fieldWithSetter(field: ArkField, baseClass: ArkClass): boolean {
        const methods = baseClass.getMethods();
        for (const method of methods) {
            if (!method.getName().startsWith('Set-')) {
                continue;
            }
            const stmts = method.getCfg()?.getStmts();
            if (stmts === undefined) {
                continue;
            }
            for (const stmt of stmts) {
                if (!(stmt instanceof ArkAssignStmt)) {
                    continue;
                }
                const leftOp = stmt.getLeftOp();
                if (!(leftOp instanceof AbstractFieldRef)) {
                    continue;
                }
                if (field.getName() === leftOp.getFieldName()) {
                    return true;
                }
            }
        }
        return false;
    }

    private checkAllArgsOfParameter(stmt: Stmt, hasChecked: Map<Local, [IssueReason, NumberCategory]>, numberCategory: NumberCategory): IssueReason {
        let checkAll = { value: true };
        let visited: Set<Stmt> = new Set();
        const result = this.checkFromStmt(stmt, hasChecked, numberCategory, checkAll, visited);
        if (!checkAll.value) {
            return IssueReason.CannotFindAll;
        }
        return result;
    }

    private checkClosureFieldRef(
        closureRef: ClosureFieldRef,
        hasChecked: Map<Local, [IssueReason, NumberCategory]>,
        numberCategory: NumberCategory
    ): IssueReason {
        const closureBase = closureRef.getBase();
        const baseType = closureBase.getType();
        if (!(baseType instanceof LexicalEnvType)) {
            // 此场景应该不可能出现，如果出现说明IR解析错误
            logger.error(`ClosureRef base must be LexicalEnvType, but here is ${baseType.getTypeString()}`);
            return IssueReason.Other;
        }
        const outerLocal = baseType.getClosures().filter(local => local.getName() === closureRef.getFieldName());
        if (outerLocal.length !== 1) {
            logger.error('Failed to find the local from outer method of the closure local.');
            return IssueReason.Other;
        }
        const declaringStmt = outerLocal[0].getDeclaringStmt();
        if (declaringStmt === null) {
            logger.error('Failed to find the declaring stmt of the local from outer method of the closure local.');
            return IssueReason.Other;
        }
        return this.isLocalOnlyUsedAsIntLong(declaringStmt, outerLocal[0], hasChecked, numberCategory);
    }

    private checkFromStmt(
        stmt: Stmt,
        hasChecked: Map<Local, [IssueReason, NumberCategory]>,
        numberCategory: NumberCategory,
        checkAll: { value: boolean },
        visited: Set<Stmt>
    ): IssueReason {
        const method = stmt.getCfg().getDeclaringMethod();
        if (!this.visited.has(method)) {
            this.dvfgBuilder.buildForSingleMethod(method);
            this.visited.add(method);
        }

        const node = this.dvfg.getOrNewDVFGNode(stmt);
        let workList: DVFGNode[] = [node];
        while (workList.length > 0) {
            const current = workList.shift()!;
            const currentStmt = current.getStmt();
            if (visited.has(currentStmt)) {
                continue;
            }
            visited.add(currentStmt);

            const paramRef = this.isFromParameter(currentStmt);
            if (paramRef) {
                const paramIdx = paramRef.getIndex();
                const callsites = this.cg.getInvokeStmtByMethod(currentStmt.getCfg().getDeclaringMethod().getSignature());
                this.processCallsites(callsites);
                const argMap = this.collectCallSiteArgs(paramIdx, callsites);
                this.callDepth++;
                if (this.callDepth > CALL_DEPTH_LIMIT) {
                    checkAll.value = false;
                    return IssueReason.CannotFindAll;
                }
                for (const [callSite, arg] of argMap) {
                    const res = this.checkValueOnlyUsedAsIntLong(callSite, arg, hasChecked, numberCategory);
                    if (res !== IssueReason.OnlyUsedAsIntLong) {
                        return res;
                    }
                }
                return IssueReason.OnlyUsedAsIntLong;
            }
        }
        return IssueReason.Other;
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

    private collectCallSiteArgs(argIdx: number, callsites: Stmt[]): Map<Stmt, Value> {
        const argMap = new Map<Stmt, Value>();
        callsites.forEach(callsite => {
            argMap.set(callsite, callsite.getInvokeExpr()!.getArg(argIdx));
        });
        return argMap;
    }

    private addIssueReport(
        ruleCategory: RuleCategory,
        numberCategory: NumberCategory,
        reason: IssueReason,
        couldAutofix: boolean,
        issueStmt?: Stmt,
        value?: Value,
        field?: ArkField,
        usedStmt?: Stmt
    ): void {
        const severity = this.rule.alert ?? this.metaData.severity;
        let warnInfo: WarnInfo;
        if (field === undefined) {
            if (issueStmt && value) {
                warnInfo = getLineAndColumn(issueStmt, value, true);
            } else {
                logger.error('Missing stmt or value when adding issue.');
                return;
            }
        } else {
            warnInfo = {
                line: field.getOriginPosition().getLineNo(),
                startCol: field.getOriginPosition().getColNo(),
                endCol: field.getOriginPosition().getColNo(),
                filePath: field.getDeclaringArkClass().getDeclaringArkFile().getFilePath(),
            };
        }
        let problem: string;
        let desc: string;
        if (ruleCategory === RuleCategory.SDKIntType) {
            problem = 'SDKIntType-' + reason;
            if (reason === IssueReason.OnlyUsedAsIntLong) {
                if (usedStmt) {
                    desc = `It has relationship with the arg of SDK API in ${this.getUsedStmtDesc(usedStmt, issueStmt)} and only used as ${numberCategory}, should be defined as ${numberCategory} (${ruleCategory})`;
                } else {
                    logger.error('Missing used stmt when getting issue description');
                    return;
                }
            } else {
                desc = `The arg of SDK API should be ${numberCategory} here (${ruleCategory})`;
            }
        } else {
            logger.error(`Have not support rule ${ruleCategory} yet.`);
            return;
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
            couldAutofix
        );

        if (couldAutofix) {
            const autofix = this.generateRuleFix(warnInfo, reason, numberCategory, issueStmt, value, field);
            if (autofix === null) {
                defects.fixable = false;
                this.issues.push(new IssueReport(defects, undefined));
            } else {
                this.issues.push(new IssueReport(defects, autofix));
            }
        } else {
            this.issues.push(new IssueReport(defects, undefined));
        }
    }

    private getUsedStmtDesc(usedStmt: Stmt, issueStmt?: Stmt): string {
        const issueFile = issueStmt?.getCfg().getDeclaringMethod().getDeclaringArkFile();
        const usedFile = usedStmt.getCfg().getDeclaringMethod().getDeclaringArkFile();
        const line = usedStmt.getOriginPositionInfo().getLineNo();
        if (issueFile && issueFile !== usedFile) {
            return `${path.normalize(usedFile.getName())}: ${line}`;
        }
        return `line ${line}`;
    }

    private generateRuleFix(
        warnInfo: WarnInfo,
        issueReason: IssueReason,
        numberCategory: NumberCategory,
        stmt?: Stmt,
        value?: Value,
        field?: ArkField
    ): RuleFix | null {
        let arkFile: ArkFile;
        if (field) {
            arkFile = field.getDeclaringArkClass().getDeclaringArkFile();
        } else if (stmt) {
            arkFile = stmt.getCfg().getDeclaringMethod().getDeclaringArkFile();
        } else {
            logger.error('Missing both issue stmt and field when generating auto fix info.');
            return null;
        }
        const sourceFile = AstTreeUtils.getASTNode(arkFile.getName(), arkFile.getCode());
        if (field) {
            // warnInfo中对于field的endCol与startCol一样，均为filed首列位置，包含修饰符位置，这里autofix采用整行替换方式进行
            const range = FixUtils.getLineRangeWithStartCol(sourceFile, warnInfo.line, warnInfo.startCol);
            if (range === null) {
                logger.error('Failed to getting range info of issue file when generating auto fix info.');
                return null;
            }
            const valueString = FixUtils.getSourceWithRange(sourceFile, range);
            if (valueString === null) {
                logger.error('Failed to getting text of the fix range info when generating auto fix info.');
                return null;
            }
            const fixedText = this.generateFixedTextForFieldDefine(valueString, numberCategory);
            if (fixedText === null) {
                logger.error('Failed to get fix text when generating auto fix info.');
                return null;
            }
            const ruleFix = new RuleFix();
            ruleFix.range = range;
            ruleFix.text = fixedText;
            return ruleFix;
        }

        if (issueReason === IssueReason.OnlyUsedAsIntLong) {
            // warnInfo中对于变量声明语句的位置信息只包括变量名，不包括变量声明时的类型注解位置，此处获取变量名后到行尾的字符串信息，替换‘: number’ 或增加 ‘: int’
            const range = FixUtils.getLineRangeWithStartCol(sourceFile, warnInfo.line, warnInfo.endCol);
            if (range === null) {
                logger.error('Failed to getting range info of issue file when generating auto fix info.');
                return null;
            }
            const valueString = FixUtils.getSourceWithRange(sourceFile, range);
            if (valueString === null) {
                logger.error('Failed to getting text of the fix range info when generating auto fix info.');
                return null;
            }
            const fixedText = this.generateFixedTextForVariableDefine(valueString, numberCategory);
            if (fixedText === null) {
                logger.error('Failed to get fix text when generating auto fix info.');
                return null;
            }
            const ruleFix = new RuleFix();
            ruleFix.range = range;
            ruleFix.text = fixedText;
            return ruleFix;
        }
        // 强转场景，获取到对应位置信息，在其后添加'.toInt()'或'.toLong()'
        let endLine = warnInfo.line;
        if (warnInfo.endLine !== undefined) {
            endLine = warnInfo.endLine;
        }
        const range = FixUtils.getRangeWithAst(sourceFile, {
            startLine: warnInfo.line,
            startCol: warnInfo.startCol,
            endLine: endLine,
            endCol: warnInfo.endCol,
        });
        if (range === null) {
            logger.error('Failed to getting range info of issue file when generating auto fix info.');
            return null;
        }
        const valueString = FixUtils.getSourceWithRange(sourceFile, range);
        if (valueString === null) {
            logger.error('Failed to getting text of the fix range info when generating auto fix info.');
            return null;
        }
        const ruleFix = new RuleFix();
        ruleFix.range = range;
        if (value === undefined) {
            logger.error('Missing issue SDK arg when generating auto fix info.');
            return null;
        }
        let transStr: string;
        if (numberCategory === NumberCategory.int) {
            transStr = '.toInt()';
        } else if (numberCategory === NumberCategory.long) {
            transStr = '.toLong()';
        } else {
            logger.error(`Have not support number category ${numberCategory} yet.`);
            return null;
        }
        if (value instanceof Local) {
            if (!value.getName().startsWith(TEMP_LOCAL_PREFIX)) {
                ruleFix.text = `${valueString}${transStr}`;
                return ruleFix;
            }
            const declaringStmt = value.getDeclaringStmt();
            if (declaringStmt === null) {
                ruleFix.text = `(${valueString})${transStr}`;
                return ruleFix;
            }
            if (declaringStmt instanceof ArkAssignStmt) {
                const rightOp = declaringStmt.getRightOp();
                if (rightOp instanceof AbstractInvokeExpr || rightOp instanceof AbstractFieldRef || rightOp instanceof ArkArrayRef) {
                    ruleFix.text = `${valueString}${transStr}`;
                    return ruleFix;
                }
                ruleFix.text = `(${valueString})${transStr}`;
                return ruleFix;
            }
            logger.error('Temp local declaring stmt must be assign stmt.');
            return null;
        } else {
            ruleFix.text = `(${valueString})${transStr}`;
            return ruleFix;
        }
    }

    private generateFixedTextForFieldDefine(originalText: string, numberCategory: NumberCategory): string | null {
        // 对于类属性private a: number 或 private a, originalText为private开始到行尾的内容，需要替换为private a: int
        let newTypeStr: string;
        if (numberCategory === NumberCategory.int) {
            newTypeStr = this.intTypeName;
        } else if (numberCategory === NumberCategory.long) {
            newTypeStr = this.longTypeName;
        } else {
            logger.error(`Have not support number category ${numberCategory} yet.`);
            return null;
        }
        let match = originalText.match(/^([^=;]+:[^=;]+)([\s\S]*)$/);
        if (match !== null && match.length > 2) {
            return match[1].replace('number', newTypeStr) + match[2];
        }
        // 对于private a = 123，originalText为private开始到行尾的内容，需要替换为private a: int = 123
        match = originalText.match(/^([^=;]+)([\s\S]*)$/);
        if (match !== null && match.length > 2) {
            return `${match[1].trimEnd()}: ${newTypeStr} ${match[2]}`;
        }
        return null;
    }

    private generateFixedTextForVariableDefine(originalText: string, numberCategory: NumberCategory): string | null {
        // 对于let a = xxx, originalText为' = xxx,'，需要替换成': int = xxx'
        // 对于let a: number | null = xxx, originalText为': number | null = xxx,'，需要替换成': int | null = xxx'
        // 对于foo(a: number, b: string)场景, originalText为‘: number, b: string)’，需要替换为foo(a: int, b: string)
        // 场景1：变量或类属性定义或函数入参，无类型注解的场景，直接在originalText前面添加': int'
        let newTypeStr: string;
        if (numberCategory === NumberCategory.int) {
            newTypeStr = this.intTypeName;
        } else if (numberCategory === NumberCategory.long) {
            newTypeStr = this.longTypeName;
        } else {
            logger.error(`Have not support number category ${numberCategory} yet.`);
            return null;
        }
        if (!originalText.trimStart().startsWith(':')) {
            if (originalText.startsWith(';') || originalText.startsWith(FixUtils.getTextEof(originalText))) {
                return `: ${newTypeStr}${originalText}`;
            }
            return `: ${newTypeStr} ${originalText.trimStart()}`;
        }
        // 场景2：变量或类属性定义或函数入参，有类型注解的场景
        const match = originalText.match(/^(\s*:[^,)=;]+)([\s\S]*)$/);
        if (match === null || match.length < 3) {
            return null;
        }
        const newAnnotation = match[1].replace('number', newTypeStr);
        return newAnnotation + match[2];
    }
}
