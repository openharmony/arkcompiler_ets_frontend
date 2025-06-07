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

import path from 'path';
import {
    ArkMethod,
    ArkAssignStmt,
    FieldSignature,
    Stmt,
    Scene,
    Value,
    DVFGBuilder,
    ArkInstanceOfExpr,
    CallGraph,
    ArkParameterRef,
    ArkInstanceFieldRef,
    ArkNamespace,
    Local,
    ArkCastExpr,
    ClassType,
    classSignatureCompare,
    ArkField,
    fileSignatureCompare,
    Cfg,
    BasicBlock,
    ArkIfStmt,
    ArkUnopExpr,
} from 'arkanalyzer/lib';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, MatcherCallback } from '../../Index';
import { IssueReport } from '../../model/Defects';
import { DVFG, DVFGNode } from 'arkanalyzer/lib/VFG/DVFG';
import { CALL_DEPTH_LIMIT, getGlobalsDefineInDefaultMethod, GlobalCallGraphHelper } from './Utils';
import { WarnInfo } from '../../utils/common/Utils';
import { ClassCategory } from 'arkanalyzer/lib/core/model/ArkClass';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'NoTSLikeAsCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
};

export class NoTSLikeAsCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];
    private cg: CallGraph;
    private dvfg: DVFG;
    private dvfgBuilder: DVFGBuilder;
    private visited: Set<ArkMethod> = new Set();

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: undefined,
            callback: this.check,
        };
        return [matchBuildCb];
    }

    public check = (scene: Scene): void => {
        this.cg = GlobalCallGraphHelper.getCGInstance(scene);

        this.dvfg = new DVFG(this.cg);
        this.dvfgBuilder = new DVFGBuilder(this.dvfg, scene);

        for (let arkFile of scene.getFiles()) {
            // 此规则仅对arkts1.1和arkts1.2进行检查，typescript在编译阶段会报错，javascript没有类型断言语法
            if (!(arkFile.getLanguage() === Language.ARKTS1_1 || arkFile.getLanguage() === Language.ARKTS1_2)) {
                continue;
            }
            const defaultMethod = arkFile.getDefaultClass().getDefaultArkMethod();
            let globalVarMap: Map<string, Stmt[]> = new Map();
            if (defaultMethod) {
                this.dvfgBuilder.buildForSingleMethod(defaultMethod);
                globalVarMap = getGlobalsDefineInDefaultMethod(defaultMethod);
            }
            for (let clazz of arkFile.getClasses()) {
                for (let field of clazz.getFields()) {
                    this.processClassField(field, globalVarMap, scene);
                }
                for (let mtd of clazz.getMethods()) {
                    this.processArkMethod(mtd, globalVarMap, scene);
                }
            }
            for (let namespace of arkFile.getAllNamespacesUnderThisFile()) {
                this.processNameSpace(namespace, globalVarMap, scene);
            }
        }
    };

    public processNameSpace(namespace: ArkNamespace, globalVarMap: Map<string, Stmt[]>, scene: Scene): void {
        for (let ns of namespace.getNamespaces()) {
            this.processNameSpace(ns, globalVarMap, scene);
        }
        for (let clazz of namespace.getClasses()) {
            for (let field of clazz.getFields()) {
                this.processClassField(field, globalVarMap, scene);
            }
            for (let mtd of clazz.getMethods()) {
                this.processArkMethod(mtd, globalVarMap, scene);
            }
        }
    }

    public processClassField(field: ArkField, globalVarMap: Map<string, Stmt[]>, scene: Scene): void {
        const stmts = field.getInitializer();
        for (const stmt of stmts) {
            const castExpr = this.getCastExpr(stmt);
            if (castExpr === null) {
                continue;
            }
            // 判断cast类型断言的类型是否是class，非class的场景不在本规则检查范围内
            if (!(castExpr.getType() instanceof ClassType)) {
                continue;
            }
            let checkAll = { value: true };
            let visited: Set<Stmt> = new Set();
            const result = this.checkFromStmt(stmt, scene, globalVarMap, checkAll, visited);
            if (result !== null) {
                this.addIssueReport(stmt, castExpr, result);
            } else {
                if (!checkAll.value) {
                    this.addIssueReport(stmt, castExpr);
                }
            }
        }
    }

    public processArkMethod(target: ArkMethod, globalVarMap: Map<string, Stmt[]>, scene: Scene): void {
        const stmts = target.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            // cast表达式所在语句为sink点，从该点开始进行逆向数据流分析
            const castExpr = this.getCastExpr(stmt);
            if (castExpr === null) {
                continue;
            }
            // 判断cast类型断言的类型是否是class，非class的场景不在本规则检查范围内
            if (!(castExpr.getType() instanceof ClassType)) {
                continue;
            }
            if (this.hasCheckedWithInstanceof(stmt.getCfg(), stmt)) {
                continue;
            }
            if (!this.visited.has(target)) {
                this.dvfgBuilder.buildForSingleMethod(target);
                this.visited.add(target);
            }

            let checkAll = { value: true };
            let visited: Set<Stmt> = new Set();
            const result = this.checkFromStmt(stmt, scene, globalVarMap, checkAll, visited);
            if (result !== null) {
                this.addIssueReport(stmt, castExpr, result);
            } else {
                if (!checkAll.value) {
                    this.addIssueReport(stmt, castExpr);
                }
            }
        }
    }

    private hasCheckedWithInstanceof(cfg: Cfg, stmt: Stmt): boolean {
        const castExpr = this.getCastExpr(stmt);
        if (castExpr === null) {
            return false;
        }
        for (const block of cfg.getBlocks()) {
            // 这里仅判断了cast op是否进行了instanceof判断，如果op是由op1赋值，op1进行了instanceof判断，此处不认为是做了有效检查
            // TODO: 还需进行复杂条件中包含类型守卫判断的情况，涉及&&，||等的复合
            const positiveCheck = this.isCastExprWithTypeAssurancePositive(block, castExpr);
            const negativeCheck = this.isCastExprWithTypeAssuranceNegative(block, castExpr);
            if (!(positiveCheck || negativeCheck)) {
                continue;
            }
            let checkedBB: Set<number> = new Set<number>();
            let needCheckBB: number[] = [];
            checkedBB.add(block.getId());
            const allSuccessors = block.getSuccessors();
            if (allSuccessors.length > 0 && positiveCheck) {
                needCheckBB.push(allSuccessors[0].getId());
            }
            if (allSuccessors.length > 1 && negativeCheck) {
                needCheckBB.push(allSuccessors[1].getId());
            }
            while (needCheckBB.length > 0) {
                const bbId = needCheckBB.shift();
                if (bbId === undefined) {
                    break;
                }
                if (checkedBB.has(bbId)) {
                    continue;
                }
                checkedBB.add(bbId);
                const bb = this.getBlockWithId(bbId, cfg);
                if (bb === null) {
                    continue;
                }
                if (this.isStmtInBlock(stmt, bb)) {
                    return true;
                } else {
                    bb.getSuccessors().forEach(b => needCheckBB.push(b.getId()));
                }
            }
        }
        return false;
    }

    private isStmtInBlock(stmt: Stmt, block: BasicBlock): boolean {
        for (const s of block.getStmts()) {
            if (s === stmt) {
                return true;
            }
        }
        return false;
    }

    private getBlockWithId(id: number, cfg: Cfg): BasicBlock | null {
        const blocks = cfg.getBlocks();
        for (const bb of blocks) {
            if (bb.getId() === id) {
                return bb;
            }
        }
        return null;
    }

    private isCastExprWithTypeAssurancePositive(bb: BasicBlock, castExpr: ArkCastExpr): boolean {
        for (const stmt of bb.getStmts()) {
            if (!(stmt instanceof ArkIfStmt)) {
                continue;
            }
            const conditionExpr = stmt.getConditionExpr();
            const op1 = conditionExpr.getOp1();
            const op2 = conditionExpr.getOp2();
            if (op1 instanceof Local) {
                const declareStmt = op1.getDeclaringStmt();
                if (declareStmt !== null && this.isStmtWithTypeAssurancePositive(declareStmt, castExpr)) {
                    return true;
                }
            }
            if (op2 instanceof Local) {
                const declareStmt = op2.getDeclaringStmt();
                if (declareStmt !== null && this.isStmtWithTypeAssurancePositive(declareStmt, castExpr)) {
                    return true;
                }
            }
        }
        return false;
    }

    private isCastExprWithTypeAssuranceNegative(bb: BasicBlock, castExpr: ArkCastExpr): boolean {
        for (const stmt of bb.getStmts()) {
            if (!(stmt instanceof ArkIfStmt)) {
                continue;
            }
            const conditionExpr = stmt.getConditionExpr();
            const op1 = conditionExpr.getOp1();
            const op2 = conditionExpr.getOp2();
            if (op1 instanceof Local) {
                const declareStmt = op1.getDeclaringStmt();
                if (declareStmt !== null && this.isStmtWithTypeAssuranceNegative(declareStmt, castExpr)) {
                    return true;
                }
            }
            if (op2 instanceof Local) {
                const declareStmt = op2.getDeclaringStmt();
                if (declareStmt !== null && this.isStmtWithTypeAssuranceNegative(declareStmt, castExpr)) {
                    return true;
                }
            }
        }
        return false;
    }

    private isStmtWithTypeAssurancePositive(declareStmt: Stmt, castExpr: ArkCastExpr): boolean {
        if (!(declareStmt instanceof ArkAssignStmt)) {
            return false;
        }
        const rightOp = declareStmt.getRightOp();
        if (!(rightOp instanceof ArkInstanceOfExpr)) {
            return false;
        }
        const castOp = castExpr.getOp();
        const castType = castExpr.getType();
        const instanceofType = rightOp.getCheckType();
        if (castType.getTypeString() !== instanceofType.getTypeString()) {
            return false;
        }
        const instanceofOp = rightOp.getOp();
        if (!(castOp instanceof Local && instanceofOp instanceof Local)) {
            return false;
        }
        return castOp.getName() === instanceofOp.getName();
    }

    private isStmtWithTypeAssuranceNegative(declareStmt: Stmt, castExpr: ArkCastExpr): boolean {
        if (!(declareStmt instanceof ArkAssignStmt)) {
            return false;
        }
        const rightOp = declareStmt.getRightOp();
        if (!(rightOp instanceof ArkUnopExpr && rightOp.getOperator() === '!')) {
            return false;
        }
        const unaryOp = rightOp.getOp();
        if (!(unaryOp instanceof Local)) {
            return false;
        }
        const unaryOpDeclareStmt = unaryOp.getDeclaringStmt();
        if (unaryOpDeclareStmt === null || !(unaryOpDeclareStmt instanceof ArkAssignStmt)) {
            return false;
        }
        const unaryOpRightOp = unaryOpDeclareStmt.getRightOp();
        if (!(unaryOpRightOp instanceof ArkInstanceOfExpr)) {
            return false;
        }
        const castOp = castExpr.getOp();
        const castType = castExpr.getType();
        const instanceofType = unaryOpRightOp.getCheckType();
        if (castType.getTypeString() !== instanceofType.getTypeString()) {
            return false;
        }
        const instanceofOp = unaryOpRightOp.getOp();
        if (!(castOp instanceof Local && instanceofOp instanceof Local)) {
            return false;
        }
        return castOp.getName() === instanceofOp.getName();
    }

    private checkFromStmt(
        stmt: Stmt,
        scene: Scene,
        globalVarMap: Map<string, Stmt[]>,
        checkAll: { value: boolean },
        visited: Set<Stmt>,
        depth: number = 0
    ): Stmt | null {
        if (depth > CALL_DEPTH_LIMIT) {
            checkAll.value = false;
            return null;
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
            if (this.isWithInterfaceAnnotation(currentStmt, scene)) {
                return currentStmt;
            }
            const gv = this.checkIfCastOpIsGlobalVar(currentStmt);
            if (gv) {
                const globalDefs = globalVarMap.get(gv.getName());
                if (globalDefs === undefined) {
                    const importValue = this.checkIfCastOpIsFromImport(currentStmt);
                    if (importValue && importValue.getDeclaringStmt() !== null) {
                        worklist.push(this.dvfg.getOrNewDVFGNode(importValue.getDeclaringStmt()!));
                    }
                } else {
                    globalDefs.forEach(d => worklist.push(this.dvfg.getOrNewDVFGNode(d)));
                }
                continue;
            }

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
                    const res = this.checkFromStmt(stmt, scene, globalVarMap, checkAll, visited, depth + 1);
                    if (res !== null) {
                        return res;
                    }
                }
            }
            const paramRef = this.isFromParameter(currentStmt);
            if (paramRef) {
                const paramIdx = paramRef.getIndex();
                const callsites = this.cg.getInvokeStmtByMethod(
                    currentStmt.getCfg().getDeclaringMethod().getSignature()
                );
                this.processCallsites(callsites);
                const argDefs = this.collectArgDefs(paramIdx, callsites);
                for (const stmt of argDefs) {
                    const res = this.checkFromStmt(stmt, scene, globalVarMap, checkAll, visited, depth + 1);
                    if (res !== null) {
                        return res;
                    }
                }
            }
            current.getIncomingEdge().forEach(e => worklist.push(e.getSrcNode() as DVFGNode));
        }
        return null;
    }

    private checkIfCastOpIsGlobalVar(stmt: Stmt): Local | undefined {
        const obj = this.getCastOp(stmt);
        if (obj instanceof Local && !obj.getDeclaringStmt()) {
            return obj;
        }
        return undefined;
    }

    private checkIfCastOpIsFromImport(stmt: Stmt): Local | undefined {
        const obj = this.getCastOp(stmt);
        if (obj === null || !(obj instanceof Local)) {
            return undefined;
        }
        const importInfos = stmt.getCfg().getDeclaringMethod().getDeclaringArkFile().getImportInfos();
        for (const importInfo of importInfos) {
            if (importInfo.getImportClauseName() === obj.getName()) {
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

    // 判断语句是否为赋值语句，且左值的类型注解为Interface，右值的类型与左值不一样
    private isWithInterfaceAnnotation(stmt: Stmt, scene: Scene): boolean {
        if (!(stmt instanceof ArkAssignStmt)) {
            return false;
        }
        const leftOpType = stmt.getLeftOp().getType();
        if (!(leftOpType instanceof ClassType)) {
            return false;
        }
        const leftOpTypeclass = scene.getClass(leftOpType.getClassSignature());
        if (leftOpTypeclass === null) {
            return false;
        }
        if (leftOpTypeclass.getCategory() !== ClassCategory.INTERFACE) {
            return false;
        }
        const rightOpType = stmt.getRightOp().getType();
        if (!(rightOpType instanceof ClassType)) {
            return true;
        }
        return !classSignatureCompare(leftOpType.getClassSignature(), rightOpType.getClassSignature());
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

    private getCastOp(stmt: Stmt): Value | null {
        if (!(stmt instanceof ArkAssignStmt)) {
            return null;
        }
        const rightOp = stmt.getRightOp();
        if (!(rightOp instanceof ArkCastExpr)) {
            return null;
        }
        return rightOp.getOp();
    }

    private getCastExpr(stmt: Stmt): ArkCastExpr | null {
        // method中使用as断言的地方可能是body体中，函数调用的实参，返回值，均会表示成ArkAssignStmt
        if (!(stmt instanceof ArkAssignStmt)) {
            return null;
        }
        const rightOp = stmt.getRightOp();
        if (!(rightOp instanceof ArkCastExpr)) {
            return null;
        }
        return rightOp;
    }

    private collectArgDefs(argIdx: number, callsites: Stmt[]): Stmt[] {
        const getKey = (v: Value): Value | FieldSignature => {
            return v instanceof ArkInstanceFieldRef ? v.getFieldSignature() : v;
        };
        return callsites.flatMap(callsite => {
            const target: Value | FieldSignature = getKey(callsite.getInvokeExpr()!.getArg(argIdx));
            return Array.from(this.dvfg.getOrNewDVFGNode(callsite).getIncomingEdge())
                .map(e => (e.getSrcNode() as DVFGNode).getStmt())
                .filter(s => {
                    return s instanceof ArkAssignStmt && target === getKey(s.getLeftOp());
                });
        });
    }

    private addIssueReport(stmt: Stmt, operand: ArkCastExpr, relatedStmt?: Stmt): void {
        const severity = this.rule.alert ?? this.metaData.severity;
        const warnInfo = this.getLineAndColumn(stmt, operand);
        const problem = 'As';
        const descPrefix = 'The value in type assertion is assigned by value with interface annotation';
        let desc = `(${this.rule.ruleId.replace('@migration/', '')})`;

        if (relatedStmt === undefined) {
            desc = `Can not find all assignments of the value in type assertion, please check it manually ` + desc;
        } else {
            const sinkFile = stmt.getCfg().getDeclaringMethod().getDeclaringArkFile();
            const relatedFile = relatedStmt.getCfg().getDeclaringMethod().getDeclaringArkFile();
            if (fileSignatureCompare(sinkFile.getFileSignature(), relatedFile.getFileSignature())) {
                desc = `${descPrefix} in Line ${relatedStmt.getOriginPositionInfo().getLineNo()} ` + desc;
            } else {
                desc = `${descPrefix} in file ${path.normalize(relatedFile.getName())}: ${relatedStmt.getOriginPositionInfo().getLineNo()} ` + desc;
            }
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
        const arkFile = stmt.getCfg()?.getDeclaringMethod().getDeclaringArkFile();
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
