/*
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

let GeneratedImportVar_1 = ESValue.load('./no_await_js_promise_export');
let p = GeneratedImportVar_1.getProperty('p');
let foo = GeneratedImportVar_1.getProperty('foo');
let pFuncCall = GeneratedImportVar_1.getProperty('pFuncCall');
let arrowFunc = GeneratedImportVar_1.getProperty('arrowFunc');
let pArrowCall = GeneratedImportVar_1.getProperty('pArrowCall');


async function awaitPromise() {
  return await p.toPromise();
}

async function awaitFunctionCall() {
  return await foo.invoke().toPromise();
}

async function awaitFuncResult() {
  return await pFuncCall.toPromise();
}

async function awaitArrowCall() {
  return await arrowFunc();
}

async function awaitArrowResult() {
  return await pArrowCall.toPromise();
}

class ExampleClass {
  async classMethod() {
    return await p.toPromise();
  }

  handler = async () => {
    return await pFuncCall.toPromise();
  };
}

const exampleObj = {
  async objMethod() {
    return await pArrowCall.toPromise();
  },

  arrowHandler: async () => {
    return await foo.invoke().toPromise();
  }
};

(async () => {
    console.log("IIFE result:", await p);
})();

(async () => {
  console.log("IIFE Arrow result:", await arrowFunc());
})();