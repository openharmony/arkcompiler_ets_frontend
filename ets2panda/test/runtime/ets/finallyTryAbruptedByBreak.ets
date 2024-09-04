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

function main() : void{
  let a = 0;
  let b = 0;
  try {
    loop:for (let i = 0; i < 10; i++) {
      try {
        for(let j = 0; j < 10; j++) {
          try {
            break loop;
          } catch (e) {
            assert(false);
          } finally {
            b++;
          }
        }
      } catch (e) {
        assert(false);
      } finally {
        a++;
      }
    }
  } catch(e) {
    assert(false);
  } finally {
    a++;
    b++;
  }
  assert(b == 2);
  assert(a == 2);

  a = 0;
  b = 0;
  try {
    loop:for (let i = 0; i < 10; i++) {
      try {
        for(let j = 0; j < 10; j++) {
          try {
            break;
          } catch (e) {
            assert(false);
          } finally {
            b++;
          }
        }
      } catch (e) {
        assert(false);
      } finally {
        a++;
      }
    }
  } catch(e) {
    assert(false);
  } finally {
    a++;
    b++;
  }
  assert(b == 11);
  assert(a == 11);
}
