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

/**
 * This is a sample class.
 */
declare class MyClass {
  name: string;

  /**
   * Constructor for MyClass.
   * @param {string} name - The name parameter.
   */
  constructor(name: string);

  /**
   * A simple function.
   * @param {number} x - The first number.
   * @param {number} y - The second number.
   * @returns {number} The sum of x and y.
   */
  add(x: number, y: number): number;

  /**
   * A method that greets.
   * @param {string} greeting - The greeting message.
   */
  greet(greeting: string): void;
}

/**
 * A simple function declaration.
 * @param {string} message - The message parameter.
 * @returns {string} The formatted message.
 */
declare function formatMessage(message: string): string;

/**
 * An interface representing a point.
 * @interface
 */
declare interface Point {
  x: number;
  y: number;
}

/**
 * A type alias for a callback function.
 * @typedef {function} Callback
 * @param {string} result - The result parameter.
 */
type Callback = (result: string) => void;

/**
 * An enumeration of colors.
 * @enum {string}
 */
declare enum Color {
  Red = "RED",
  Green = "GREEN",
  Blue = "BLUE",
}
