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

interface Todo {
  title: string;
  description: string;
}
function updateTodo(todo: Todo, fieldsToUpdate: Partial<Todo>) { // OK
  return { ...todo, ...fieldsToUpdate };
}
const todo1 = {
  title: 'organize desk',
  description: 'clear clutter',
};
const todo2 = updateTodo(todo1, {
  description: 'throw out trash',
});

let numberPartial: Partial<number> = 1; // NOT OK
type StringPartial = Partial<string>; // NOT OK 

// Initializing Partial<T>
interface Style {
  color: number;
}

function applyStyle(arg: Partial<Style>) { }
applyStyle({}); // Ok
applyStyle({color: 0x123456}); // Ok

// Partial with type alias
type PART = Partial<Style>;
let part: PART = {}; // Ok, 
part = {color: 0xFFFFFF}; // Ok