/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

interface Mover {
  move(): void;
  getStatus(): { speed: number };
}

interface Shaker {
  shake(): void;
  getStatus(): { frequency: number };
}

interface MoverShaker extends Mover, Shaker {
  getStatus(): { speed: number; frequency: number };
}

class C implements MoverShaker {
  move(): void {
    console.log("move");
  }

  shake(): void {
    console.log("shake");
  }

  getStatus() {
    const speed = 100;
    const frequency = 300;
    return { speed, frequency };
  }
}

const c = new C();
c.move();
c.shake();

const st = c.getStatus();
console.log(st);

const obj: Object = c;

if (obj && obj.move && obj.shake && obj.getStatus) {
  const moverShaker = obj as MoverShaker;

  console.log(moverShaker);
}
