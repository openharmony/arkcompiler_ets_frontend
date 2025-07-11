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
    Stmt,
    Scene,
    Value,
    ArkInstanceFieldRef,
    ClassType,
    ArkInvokeStmt,
    AbstractInvokeExpr,
    ArkField,
    ArkReturnStmt,
} from 'arkanalyzer/lib';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, MatcherCallback, MatcherTypes, MethodMatcher } from '../../Index';
import { IssueReport } from '../../model/Defects';
import { ArkClass, ClassCategory } from 'arkanalyzer/lib/core/model/ArkClass';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';
import { getLanguageStr, getLineAndColumn } from './Utils';
import { ArkThisRef } from 'arkanalyzer';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'InteropS2DObjectLiteralCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
};

const s2dRuleId: string = 'arkts-interop-s2d-object-literal';

type IssueData = {
    stmt: Stmt;
    value: Value;
};

export class InteropS2DObjectLiteralCheck implements BaseChecker {
    private scene: Scene;
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private methodMatcher: MethodMatcher = {
        matcherType: MatcherTypes.METHOD,
    };

    public registerMatchers(): MatcherCallback[] {
        const methodMatcher: MatcherCallback = {
            matcher: this.methodMatcher,
            callback: this.check,
        };
        return [methodMatcher];
    }

    public check = (arkMethod: ArkMethod): void => {
        this.scene = arkMethod.getDeclaringArkFile().getScene();

        if (arkMethod.getLanguage() !== Language.ARKTS1_1) {
            return;
        }
        // 检测的sink点为赋值语句，且左值的类型注解明确为1.2的class或者包含1.2的class的更复杂数据结构
        const stmts = arkMethod.getBody()?.getCfg().getStmts() ?? [];
        // 检查所有语句
        // 1. 对于赋值语句，检查左边是否为arkts1.2的class类型或某个field为arkts1.2的class类型，右边对象或对应属性是否用arkts1.1的object litral赋值
        // 2. 对于函数调用，可能为invoke语句或赋值语句的右值为invoke表达式，检查入参是否存在如上的情况
        for (const stmt of stmts) {
            if (stmt instanceof ArkAssignStmt) {
                this.checkAssignWithObjectLiteral(stmt, arkMethod);
                if (stmt.getRightOp() instanceof AbstractInvokeExpr) {
                    this.checkInvokeWithObjectLiteral(stmt, arkMethod);
                }
            } else if (stmt instanceof ArkInvokeStmt) {
                this.checkInvokeWithObjectLiteral(stmt, arkMethod);
            }
        }
        // 检查函数的返回值，若函数签名中返回类型声明是否为arkts1.2的class类型或某个field为arkts1.2的class类型，且实际返回对象或对应属性是否为arkts1.1的object litral
        this.checkReturnWithObjectLiteral(arkMethod);
    };

    private getClassWithType(checkType: ClassType): ArkClass | null {
        return this.scene.getClass(checkType.getClassSignature());
    }

    private isClassFromEtsStatic(clazz: ArkClass): boolean {
        return clazz.getLanguage() === Language.ARKTS1_2 && clazz.getCategory() !== ClassCategory.OBJECT;
    }

    private isObjectLiteralFromEtsDynamic(clazz: ArkClass): boolean {
        return clazz.getLanguage() === Language.ARKTS1_1 && clazz.getCategory() === ClassCategory.OBJECT;
    }

    private checkAssignWithObjectLiteral(stmt: ArkAssignStmt, target: ArkMethod): void {
        // this = thisRef 赋值语句需要跳过，否则该class一定会被扫描一遍，此次扫描多余，且可能会产生行号为-1的错误issue
        // 若此class有问题，会在真正使用到此class的源码处进行告警，无需查找this ref语句
        if (stmt.getRightOp() instanceof ArkThisRef) {
            return;
        }
        const leftOpType = stmt.getLeftOp().getType();
        if (!(leftOpType instanceof ClassType)) {
            return;
        }
        const leftTypeClass = this.getClassWithType(leftOpType);
        if (leftTypeClass === null) {
            logger.debug(`Failed to find class of type ${leftOpType.toString()}`);
            return;
        }
        if (this.isClassFromEtsStatic(leftTypeClass)) {
            const rightOpType = stmt.getRightOp().getType();
            if (!(rightOpType instanceof ClassType)) {
                return;
            }
            const rightTypeClass = this.getClassWithType(rightOpType);
            if (rightTypeClass === null) {
                logger.debug(`Failed to find class of type ${rightOpType.toString()}`);
                return;
            }
            if (this.isObjectLiteralFromEtsDynamic(rightTypeClass)) {
                this.addIssueReport(stmt, stmt.getRightOp());
                return;
            }
        }
        let results: IssueData[] = [];
        this.checkAllClassFieldWithValue(stmt, stmt.getRightOp(), leftTypeClass, results);
        for (const result of results) {
            this.addIssueReport(result.stmt, result.value);
        }
    }

    private checkInvokeWithObjectLiteral(stmt: ArkInvokeStmt | ArkAssignStmt, target: ArkMethod): void {
        let invokeExpr: AbstractInvokeExpr;
        if (stmt instanceof ArkInvokeStmt) {
            invokeExpr = stmt.getInvokeExpr();
        } else {
            const rightOp = stmt.getRightOp();
            if (!(rightOp instanceof AbstractInvokeExpr)) {
                return;
            }
            invokeExpr = rightOp;
        }
        const method = this.scene.getMethod(invokeExpr.getMethodSignature());
        if (method === null) {
            logger.debug(`Failed to find method in invoke expr, method: ${invokeExpr.getMethodSignature().toString()}`);
            return;
        }
        for (const [index, param] of method.getParameters().entries()) {
            const paramType = param.getType();
            if (!(paramType instanceof ClassType)) {
                continue;
            }
            const paramTypeClass = this.getClassWithType(paramType);
            if (paramTypeClass === null) {
                logger.debug(`Failed to find class of method param type ${paramType.toString()}, method: ${method.getSignature().toString()}`);
                continue;
            }
            if (index >= invokeExpr.getArgs().length) {
                logger.debug(`Failed to find param with index ${index} of method: ${method.getSignature().toString()}`);
                continue;
            }
            const arg = invokeExpr.getArg(index);
            if (this.isClassFromEtsStatic(paramTypeClass)) {
                const argType = arg.getType();
                if (!(argType instanceof ClassType)) {
                    continue;
                }
                const argTypeClass = this.getClassWithType(argType);
                if (argTypeClass === null) {
                    logger.debug(`Failed to find class of invoke arg type ${argType.toString()}, method: ${method.getSignature().toString()}`);
                    continue;
                }
                if (this.isObjectLiteralFromEtsDynamic(argTypeClass)) {
                    this.addIssueReport(stmt, arg);
                    return;
                }
            }
            let results: IssueData[] = [];
            this.checkAllClassFieldWithValue(stmt, arg, paramTypeClass, results);
            for (const result of results) {
                this.addIssueReport(result.stmt, result.value);
            }
        }
    }

    private checkReturnWithObjectLiteral(target: ArkMethod): void {
        // 构造函数的返回值一定是当前class本身，其各field和method已在其他地方进行检查，这里无需检查构造函数的返回值
        if (target.getName() === 'constructor') {
            return;
        }
        const returnType = target.getReturnType();
        if (!(returnType instanceof ClassType)) {
            return;
        }
        const returnTypeClass = this.getClassWithType(returnType);
        if (returnTypeClass === null) {
            logger.debug(`Failed to find method of return type ${returnType.toString()}, method ${target.getSignature().toString()}`);
            return;
        }
        const returnStmts = target.getReturnStmt();
        if (this.isClassFromEtsStatic(returnTypeClass)) {
            for (const returnStmt of returnStmts) {
                if (!(returnStmt instanceof ArkReturnStmt)) {
                    continue;
                }
                const valueType = returnStmt.getOp().getType();
                if (!(valueType instanceof ClassType)) {
                    continue;
                }
                const valueTypeClass = this.getClassWithType(valueType);
                if (valueTypeClass === null) {
                    logger.debug(`Failed to find method of return value type ${valueType.toString()}, method ${target.getSignature().toString()}`);
                    continue;
                }
                if (this.isObjectLiteralFromEtsDynamic(valueTypeClass)) {
                    this.addIssueReport(returnStmt, returnStmt.getOp());
                }
            }
            return;
        }

        for (const returnStmt of returnStmts) {
            if (!(returnStmt instanceof ArkReturnStmt)) {
                continue;
            }
            let results: IssueData[] = [];
            this.checkAllClassFieldWithValue(returnStmt, returnStmt.getOp(), returnTypeClass, results);
            if (results.length > 0) {
                this.addIssueReport(returnStmt, returnStmt.getOp());
            }
        }
    }

    private checkAllClassFieldWithValue(sinkStmt: Stmt, val: Value, needCheckClass: ArkClass, result: IssueData[], checkedTypes?: Set<string>): void {
        let visited: Set<string> = checkedTypes ?? new Set<string>();
        if (visited.has(needCheckClass.getSignature().toString())) {
            return;
        }
        visited.add(needCheckClass.getSignature().toString());
        for (const field of needCheckClass.getFields()) {
            const fieldType = field.getType();
            if (!(fieldType instanceof ClassType)) {
                continue;
            }
            const fieldTypeClass = this.getClassWithType(fieldType);
            if (fieldTypeClass === null) {
                logger.debug(
                    `Failed to find class of type ${fieldType.toString()} of field: ${field.getName()}, class ${needCheckClass.getSignature().toString()}}`
                );
                continue;
            }
            const fieldInitializers = this.getFieldInitializersWithValue(field, val);
            const fieldAssignStmt = this.getFieldAssignStmtInInitializers(field, fieldInitializers);
            if (fieldAssignStmt === null) {
                continue;
            }
            if (this.isClassFromEtsStatic(fieldTypeClass)) {
                const rightOpType = fieldAssignStmt.getRightOp().getType();
                if (!(rightOpType instanceof ClassType)) {
                    continue;
                }
                const rightOpTypeClass = this.getClassWithType(rightOpType);
                if (rightOpTypeClass === null) {
                    logger.debug(
                        `Failed to find class of type ${rightOpType.toString()} of field initializer, field: ${field.getName()}, class ${needCheckClass.getSignature().toString()}}`
                    );
                    continue;
                }
                if (this.isObjectLiteralFromEtsDynamic(rightOpTypeClass)) {
                    result.push({ stmt: sinkStmt, value: val });
                    continue;
                }
                continue;
            }
            this.checkAllClassFieldWithValue(fieldAssignStmt, fieldAssignStmt.getRightOp(), fieldTypeClass, result, visited);
        }
    }

    private getFieldAssignStmtInInitializers(field: ArkField, fieldInitializers: Stmt[]): ArkAssignStmt | null {
        for (const stmt of fieldInitializers) {
            if (!(stmt instanceof ArkAssignStmt)) {
                continue;
            }
            const leftOp = stmt.getLeftOp();
            if (!(leftOp instanceof ArkInstanceFieldRef)) {
                continue;
            }
            if (leftOp.getFieldName() === field.getName()) {
                return stmt;
            }
        }
        return null;
    }

    // 对于object literal（主要是多层嵌套场景），根据需要查找的field的名字，获取其对应的内部嵌套class的初始化语句
    private getFieldInitializersWithValue(leftField: ArkField, val: Value): Stmt[] {
        const res: Stmt[] = [];
        const rightOpType = val.getType();
        if (!(rightOpType instanceof ClassType)) {
            return res;
        }
        const rightOpTypeClass = this.getClassWithType(rightOpType);
        if (rightOpTypeClass === null) {
            logger.debug(`Failed to find class of type ${rightOpType.toString()} of field: ${leftField.getSignature().toString()}`);
            return res;
        }
        for (const field of rightOpTypeClass.getFields()) {
            if (field.getName() === leftField.getName()) {
                return field.getInitializer();
            }
        }
        return res;
    }

    private addIssueReport(stmt: Stmt, operand: Value): void {
        const severity = this.metaData.severity;
        let warnInfo = getLineAndColumn(stmt, operand);
        let targetLan1 = getLanguageStr(Language.ARKTS1_1);
        let targetLan2 = getLanguageStr(Language.ARKTS1_2);

        const problem = 'Interop';
        const desc = `In ${targetLan1}, it is not allowed to create object literal of type from ${targetLan2} (${s2dRuleId})`;

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
}
