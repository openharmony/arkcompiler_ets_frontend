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

export enum SdkProblem {
  LimitedVoidType = 'LimitedVoidType',
  ConstructorIface = 'ConstructorIface',
  LiteralAsPropertyName = 'LiteralAsPropertyName',
  OptionalMethod = 'OptionalMethod',
  ConstructorFuncs = 'ConstructorFuncs',
  IndexedAccessType = 'IndexedAccessType',
  SendablePropType = 'SendablePropType',
  TypeQuery = 'TypeQuery',
  GlobalThisError = 'GlobalThisError',
  InterfaceExtendsClass = 'InterfaceExtendsClass',
  DeclWithDuplicateName = 'DeclWithDuplicateName',
  ComputedPropertyName = 'ComputedPropertyName'
}

export enum SdkNameInfo {
  ParentApiName = 'parent_api_name',
  ImportPath = 'import_path'
}

export const ARKTS_WHITE_API_PATH_TEXTSTYLE = 'component/styled_string.d.ts';

// Define function argument class
export class ApiFuncArg {
  name: string;
  type: string;
  is_optional: boolean;
  has_default?: boolean;

  constructor(data: Partial<ApiFuncArg>) {
    this.name = data.name || '';
    this.type = data.type || '';
    this.is_optional = data.is_optional || false;
    this.has_default = data.has_default || undefined;
  }
}

// Define the parent API class (recursive structure)
export class ParentApi {
  api_name: string;
  api_type: string;

  constructor(data: Partial<ParentApi>) {
    this.api_name = data.api_name || '';
    this.api_type = data.api_type || '';
  }
}

// Define the API information class
export class ApiInfo {
  problem: string;
  api_name?: string;
  api_type: string;
  api_optional?: boolean;
  api_auto_fix?: boolean;
  api_auto_fix_context?: string;
  api_func_args?: ApiFuncArg[];
  parent_api: ParentApi[];
  method_return_type?: string;
  api_property_type?: string;
  code_kind: number;

  constructor(data: Partial<ApiInfo>) {
    this.problem = data.problem || '';
    this.api_name = data.api_name || undefined;
    this.api_type = data.api_type || '';
    this.api_optional = data.api_optional || undefined;
    this.api_auto_fix = data.api_auto_fix || undefined;
    this.api_auto_fix_context = data.api_auto_fix_context || undefined;
    this.api_func_args =
      (data.api_func_args || []).map((arg) => {
        return new ApiFuncArg(arg);
      }) || undefined;
    this.parent_api = (data.parent_api || []).map((parent) => {
      return new ParentApi(parent);
    });
    this.method_return_type = data.method_return_type || undefined;
    this.api_property_type = data.api_property_type || undefined;
    this.code_kind = data.code_kind || 0;
  }
}

// Define the API list item class
export class ApiListItem {
  import_path: string[];
  file_path: string;
  api_info: ApiInfo;
  is_global: boolean;

  constructor(data: Partial<ApiListItem>) {
    this.import_path = data.import_path || [];
    this.file_path = data.file_path || '';
    this.api_info = new ApiInfo(data.api_info || {});
    this.is_global = data.is_global || false;
  }
}

// Define the top-level API list class
export class ApiList {
  api_list: ApiListItem[];

  constructor(data: Partial<ApiList>) {
    this.api_list = (data.api_list || []).map((item) => {
      return new ApiListItem(item);
    });
  }
}
