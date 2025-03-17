# Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

    def all_flags_with_value
      res = {}
      dig(:flags)&.each_with_index do |flag, index|
        if type == 'int'
          res[flag] = index
        else
          res[flag] = 1 << (index - 1)
        end
      end

      dig(:flag_unions)&.each do |union|
        res[union.name] = union.flags.reduce(0) { |result, key| result | res[key] }
      end
      res
    end

    def flag_unions
      res = {}
      dig(:flag_unions)&.each { |union| res[union.name] = union.flags }
      res
    end

    def namespace
      if Enums.change_namespace.include?(dig(:namespace))
        return Enums.change_namespace[dig(:namespace)]
      else
        return dig(:namespace)
      end
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

  def get_astnodetype_value(class_name)
    enums['AstNodeType'].all_flags_with_value[class_name]
  end

  @enums = {}
  @change_namespace = {
    'ast_verifier' => 'compiler::ast_verifier', 'verifier_invariants' => 'util::gen::verifier_invariants'
  }

  attr_reader :change_namespace
  attr_reader :enums

  def wrap_data(data)
    return unless data

    data.enums&.each do |enum|
      @enums[enum.name] = EnumData.new(enum)
    end

    node_type_enum_flags = []
    scope_type_enum_flags = []
    decl_type_enum_flags = ['NONE']
    data.macros&.each do |macros|
      case macros.name
      when 'AST_NODE_MAPPING'
        node_type_enum_flags.concat(macros.values.map { |x| x[0] })
      when 'AST_NODE_REINTERPRET_MAPPING'
        node_type_enum_flags.concat(macros.values.flat_map { |x| x[0..1] })
      when 'SCOPE_TYPES'
        scope_type_enum_flags.concat(macros.values.map { |x| x[0] })
      end
    end
    data.varbinder&.macros&.each do |macros|
      case macros.name
      when 'SCOPE_TYPES'
        scope_type_enum_flags.concat(macros.values.map { |x| x[0] })
      when 'DECLARATION_KINDS'
        decl_type_enum_flags.concat(macros.values.map { |x| x[0] })
      end
    end

    unless node_type_enum_flags.empty?
      @enums['AstNodeType'] = EnumData.new(OpenStruct.new({ 'kind' => 'simple', 'flags' => node_type_enum_flags,
                                                            'namespace' => 'ir', 'name' => 'AstNodeType' }))
    end

    unless scope_type_enum_flags.empty?
      @enums['ScopeType'] = EnumData.new(OpenStruct.new({ 'kind' => 'simple', 'flags' => scope_type_enum_flags,
                                                          'namespace' => 'varbinder', 'name' => 'ScopeType' }))
    end

    return if decl_type_enum_flags.empty? || decl_type_enum_flags == ['NONE']

    @enums['DeclType'] = EnumData.new(OpenStruct.new({ 'kind' => 'simple', 'flags' => decl_type_enum_flags,
                                                       'namespace' => 'varbinder', 'name' => 'DeclType' }))
  end

  module_function :wrap_data, :enums, :change_namespace, :get_astnodetype_value
end

def Gen.on_require(data)
  Enums.wrap_data(data)
end
