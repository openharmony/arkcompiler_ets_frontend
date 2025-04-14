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

import { ArkInstanceInvokeExpr, ArkMethod, ArkStaticInvokeExpr, CallGraph, CallGraphBuilder, Stmt, Value } from 'arkanalyzer/lib';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, ClassMatcher, MethodMatcher, MatcherTypes, MatcherCallback } from '../../Index';
import { IssueReport } from '../../model/Defects';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'AppStorageGetCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: 'Get State of AppStorage in component build function, it will update UI interface when the state of AppStorage is changed.'
};

const APP_STORAGE_STR = "AppStorage";
const API_SET: Set<string> = new Set<string>(['Has', 'has', 'Get', 'get',
    'Keys', 'keys', 'IsMutable', 'Size', 'size']);

const CALLBACK_METHOD_NAME: string[] = [
    "onClick", // 点击事件，当用户点击组件时触发
    "onTouch", // 触摸事件，当手指在组件上按下、滑动、抬起时触发
    "onAppear", // 组件挂载显示时触发
    "onDisAppear", // 组件卸载消失时触发
    "onDragStart", // 拖拽开始事件，当组件被长按后开始拖拽时触发
    "onDragEnter", // 拖拽进入组件范围时触发
    "onDragMove", // 拖拽在组件范围内移动时触发
    "onDragLeave", // 拖拽离开组件范围内时触发
    "onDrop", // 拖拽释放目标，当在本组件范围内停止拖拽行为时触发
    "onKeyEvent", // 按键事件，当组件获焦后，按键动作触发
    "onFocus", // 焦点事件，当组件获取焦点时触发
    "onBlur", // 当组件失去焦点时触发的回调
    "onHover", // 鼠标悬浮事件，鼠标进入或退出组件时触发
    "onMouse", // 鼠标事件，当鼠标按键点击或在组件上移动时触发
    "onAreaChange", // 组件区域变化事件，组件尺寸、位置变化时触发
    "onVisibleAreaChange", // 组件可见区域变化事件，组件在屏幕中的显示区域面积变化时触发
];

export class AppStorageGetCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private classMatcher: ClassMatcher = {
        matcherType: MatcherTypes.CLASS,
        hasViewTree: true,
    };

    private buildMatcher: MethodMatcher = {
        matcherType: MatcherTypes.METHOD,
        class: [this.classMatcher],
        name: ["build"]
    };

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: this.buildMatcher,
            callback: this.check
        };
        return [matchBuildCb];
    }

    public check = (targetMtd: ArkMethod) => {
        const scene = targetMtd.getDeclaringArkFile().getScene();
        let callGraph = new CallGraph(scene);
        let callGraphBuilder = new CallGraphBuilder(callGraph, scene);
        callGraphBuilder.buildClassHierarchyCallGraph([targetMtd.getSignature()], true);

        this.checkMethod(targetMtd, callGraph);
    }

    private checkMethod(targetMtd: ArkMethod, cg: CallGraph, depth: number = 0) {
        if (depth > 2) {
            return;
        }
        const stmts = targetMtd.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            this.checkAppStorageGet(stmt)
            const invokeExpr = stmt.getInvokeExpr();
            if (invokeExpr && invokeExpr instanceof ArkInstanceInvokeExpr) {
                if (CALLBACK_METHOD_NAME.includes(invokeExpr.getMethodSignature().getMethodSubSignature().getMethodName())) {
                    continue;
                }
            }
            let callsite = cg.getCallSiteByStmt(stmt);
            callsite.forEach(cs => {
                let callee = cg.getArkMethodByFuncID(cs.calleeFuncID);
                if (callee) {
                    this.checkMethod(callee, cg, depth + 1);
                }
            })
        }
    }

    private checkAppStorageGet(stmt: Stmt) {
        let invokeExpr = stmt.getInvokeExpr();
        if (!(invokeExpr instanceof ArkStaticInvokeExpr)) {
            return;
        }
        const methodSig = invokeExpr.getMethodSignature();
        if (methodSig.getDeclaringClassSignature().getClassName() !== APP_STORAGE_STR) {
            return;
        }
        if (!API_SET.has(methodSig.getMethodSubSignature().getMethodName())) {
            return;
        }
        this.addIssueReport(stmt, invokeExpr);
    }

    private addIssueReport(stmt: Stmt, operand: Value) {
        const severity = this.rule.alert ?? this.metaData.severity;
        const warnInfo = this.getLineAndColumn(stmt, operand);
        let defects = new Defects(warnInfo.line, warnInfo.startCol, warnInfo.endCol, this.metaData.description, severity, this.rule.ruleId,
            warnInfo.filePath, this.metaData.ruleDocPath, true, false, false);
        this.issues.push(new IssueReport(defects, undefined));
    }

    private getLineAndColumn(stmt: Stmt, operand: Value) {
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