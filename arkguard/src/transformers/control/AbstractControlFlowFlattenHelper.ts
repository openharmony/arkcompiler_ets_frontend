/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import type {Expression, ForStatement, Statement, SwitchStatement, WhileStatement} from 'typescript';

import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';

export abstract class AbstractControlFlowFlattenHelper {
  protected mOrderObjName: string;

  protected mIndexName: string;

  protected mOriginalUnits: Statement[];

  protected mStatementUnits: Map<number, Statement>;

  protected mNameGenerator: INameGenerator;

  protected constructor(units: Statement[], reservedNames: Set<string>) {
    this.mOriginalUnits = units;
    const options: NameGeneratorOptions = {
      reservedNames: reservedNames
    };
    this.mNameGenerator = getNameGenerator(NameGeneratorType.ORDERED, options);
    this.mOrderObjName = this.mNameGenerator.getName();
    reservedNames.add(this.mOrderObjName);
    this.mIndexName = this.mNameGenerator.getName();
    reservedNames.add(this.mIndexName);
  }

  public abstract getLoopCondition(): Expression;

  public abstract getLoopStruct(): WhileStatement | ForStatement;

  public abstract getSwitchStruct(): SwitchStatement;

  public abstract getVariableRelatedStatements(): Statement[];

  public getFlattenStruct(): Statement[] {
    return [...this.getVariableRelatedStatements(), this.getLoopStruct()];
  }
}
