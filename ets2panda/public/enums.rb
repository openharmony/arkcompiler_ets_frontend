# Copyright (c) 2024 Huawei Device Co., Ltd.
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

require 'delegate'
require 'ostruct'

module Enums
  class EnumData < SimpleDelegator
    def type
      raise 'Unsupported enum kind' unless %w[simple flags].include?(kind)

      kind == 'simple' ? 'int' : 'unsigned'
    end

    def flags
      dig(:flags) || []
    end

    def flag_unions
      res = {}
      dig(:flag_unions)&.each { |union| res[union.name] = union.flags }
      res
    end

    def namespace
      dig(:namespace)
    end

    def parent_class_name
      dig(:parent_class_name)
    end

    def name_to_upper_snake
      dig(:name)&.gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
                        &.gsub(/([a-z\d])([A-Z])/, '\1_\2')
                        &.upcase
    end
  end

  @enums = {}

  def enums
    @enums
  end

  def wrap_data(data)
    return unless data

    data.enums&.each do |enum|
      @enums[enum.name] = EnumData.new(enum)
    end

    node_type_enum_flags = []
    scope_type_enum_flags = []
    data.macros&.each do |macros|
      case macros.name
      when 'AST_NODE_MAPPING'
        node_type_enum_flags.concat(macros.values&.map { |x| x[0] })
      when 'AST_NODE_REINTERPRET_MAPPING'
        node_type_enum_flags.concat(macros.values&.map { |x| x[0..1] }&.flatten)
      when 'SCOPE_TYPES'
        scope_type_enum_flags.concat(macros.values&.map { |x| x[0] })
      end
    end
    data.varbinder&.macros&.each do |macros|
      case macros.name
      when 'SCOPE_TYPES'
        scope_type_enum_flags.concat(macros.values&.map { |x| x[0] })
      end
    end

    return if node_type_enum_flags.empty?

    @enums['AstNodeType'] = EnumData.new(OpenStruct.new({ 'kind' => 'simple', 'flags' => node_type_enum_flags,
                                                          'namespace' => 'ir', 'name' => 'AstNodeType' }))

    return if scope_type_enum_flags.empty?

    @enums['ScopeType'] = EnumData.new(OpenStruct.new({ 'kind' => 'simple', 'flags' => scope_type_enum_flags,
                                                        'namespace' => 'varbinder', 'name' => 'ScopeType' }))
  end

  module_function :wrap_data, :enums
end

def Gen.on_require(data)
  Enums.wrap_data(data)
end
