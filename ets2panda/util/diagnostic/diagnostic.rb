#!/usr/bin/env ruby
# Copyright (c) 2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'ostruct'
require 'set'
require 'delegate'

module Diagnostic
  module_function

  @diagnostics = []

  def diagnostics
    @diagnostics
  end

  def wrap_data(data)
    data.each_pair do |diagnostic_type, diagnostics|
      diagnostics.each.with_index(1) do |diagnostic, index|
        diagnostic.type = diagnostic_type
        @diagnostics.append(diagnostic)
      end
    end
  end
end

def Gen.on_require(data)
  Diagnostic.wrap_data(data)
end

