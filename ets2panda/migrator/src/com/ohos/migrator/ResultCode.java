/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

package com.ohos.migrator;

public enum ResultCode {
    // values 1 and 2 have special meaning in UNIX/Linux
    // also use traditional UNIX result values from "sysexits.h"
    OK(0),
    CmdLineError(64),   //EX_USAGE
    InputError(66),     //EX_NOINPUT
    ParseError(80),     // EX_MAX + 1
    TranspileError(81); // EX_MAX + 2

    public final int value;
    ResultCode(int code) {
        this.value = code;
    }

    // select more important return code
    public static ResultCode majorValue(ResultCode currentCode, ResultCode storedCode) {
        if (currentCode == OK)
            return storedCode;

        switch (storedCode) {
            case InputError:
                return storedCode;
            case ParseError:
                return (currentCode == TranspileError) ? storedCode : currentCode;
            case OK:
            case CmdLineError:
            case TranspileError:
                return currentCode;
        }

        return OK;
    }

    public String getErrorName() {
        switch (this) {
            case CmdLineError:
                return "command-line error";
            case InputError:
                return "input file error";
            case ParseError:
                return "parse error";
            case TranspileError:
                return "transpile error";
            default:
                return "";
        }
    }
}
