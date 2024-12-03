/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

export const SENDABLE_DECORATOR = 'Sendable';

export const SENDABLE_DECORATOR_NODES = [
  ts.SyntaxKind.ClassDeclaration,
  ts.SyntaxKind.FunctionDeclaration,
  ts.SyntaxKind.TypeAliasDeclaration
];

export const SENDABLE_CLOSURE_DECLS = [ts.SyntaxKind.ClassDeclaration, ts.SyntaxKind.FunctionDeclaration];

export const SENDBALE_FUNCTION_START_VERSION = 12;
export const SENDABLE_FUNCTION_UNSUPPORTED_STAGES_IN_API12 = ['beta1', 'beta2'];
