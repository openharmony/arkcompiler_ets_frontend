/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

function templateLiterals(): void {
  const empty = ``;
  const templateText = `First line \n second line
third line \n fourth line`;
  const templateHead = `template-head ${20 + 40}`;
  const templateTail = `${empty.length > 0 ? 100 : 200} template-tail`;
  const templateCompound = `apple ${400} orange \n ${500} 
"banana" ${600} 'grapes'`;
  const nested = `outer ${`inner ${1000} inner-end`} outer-end`;
}

function tag1(strings: TemplateStringsArray): void {
  console.log(strings);
}
function tag2(strings: TemplateStringsArray, ...values: any[]): void {
  console.log(strings, values);
}
function recursiveTag(
  strings: TemplateStringsArray,
  ...values: any[]
): typeof recursiveTag {
  console.log(strings, values);
  return recursiveTag;
}

function taggedTemplates(arg: string): void {
  tag1`Birds are singing`;
  tag2`This product costs ${arg} per month`;
  recursiveTag`Hello``World`;
}
