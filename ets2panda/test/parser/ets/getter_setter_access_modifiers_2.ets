/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

class Core {
    private _size: int;
    private _width: int;

    final get size(): int {
        return this._size;
    }

    final set size(s: int): void {
        this._size = s;
    }
}

class Hex extends Core {
    private _size: int;
    private _width: int;

    override set size(s: int): void {
        this._size = s;
    }

    override get size(): int {
        return this._size;
    }
}
