/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

import * as ts from 'typescript';
import type { TsUtils } from '../TsUtils';

type CheckStdCallApi = (callExpr: ts.CallExpression) => boolean;
type StdCallApiEntry = Map<string, CheckStdCallApi>;

export class SupportedStdCallApiChecker {
  tsUtils: TsUtils;
  typeChecker: ts.TypeChecker;

  constructor(tsUtils: TsUtils, typeChecker: ts.TypeChecker) {
    this.tsUtils = tsUtils;
    this.typeChecker = typeChecker;
  }

  stdObjectEntry = new Map<string, CheckStdCallApi>([['assign', this.checkObjectAssignCall]]);

  StdCallApi = new Map<string | undefined, StdCallApiEntry>([
    ['Object', this.stdObjectEntry],
    ['ObjectConstructor', this.stdObjectEntry]
  ]);

  isSupportedStdCallAPI(callExpr: ts.CallExpression, parentSymName: string | undefined, symName: string): boolean {
    const entry = this.StdCallApi.get(parentSymName);
    if (entry) {
      const stdCallApiCheckCb = entry.get(symName);
      return !!stdCallApiCheckCb && stdCallApiCheckCb.call(this, callExpr);
    }

    return false;
  }

  private checkObjectAssignCall(callExpr: ts.CallExpression): boolean {

    /*
     * 'Object.assign' is allowed only with signature like following:
     *    assign(target: Record<string, V>, ...source: Object[]>): Record<String, V>
     *
     * Note: For 'return' type, check the contextual type of call expression, as the
     * return type of actual call signature will be deduced as an intersection of all
     * types of the 'target' and 'source' arguments.
     */

    if (callExpr.typeArguments || callExpr.arguments.length === 0) {
      return false;
    }
    const targetArgType = this.typeChecker.getTypeAtLocation(callExpr.arguments[0]);
    if (!this.isValidObjectAssignRecordType(targetArgType)) {
      return false;
    }
    const contextualType = this.typeChecker.getContextualType(callExpr);
    if (!contextualType || !this.isValidObjectAssignRecordType(contextualType)) {
      return false;
    }

    return true;
  }

  private isValidObjectAssignRecordType(type: ts.Type): boolean {
    if (this.tsUtils.isStdRecordType(type) && type.aliasTypeArguments?.length) {
      const typeArg = type.aliasTypeArguments[0];
      if (typeArg.getFlags() & (ts.TypeFlags.String | ts.TypeFlags.StringLiteral)) {
        return true;
      }
    }
    return false;
  }
}
