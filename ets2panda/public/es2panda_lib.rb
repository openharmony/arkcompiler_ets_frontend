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

require 'set'
require 'delegate'
require_relative 'enums.rb'

module Es2pandaLibApi
  class Arg
    @primitive_types = nil

    # Containers
    @es2panda_arg = nil
    @lib_args = nil
    @lib_cast = nil
    @return_args = nil
    @is_ast_node = false
    @is_ast_node_add_children = false
    @is_ast_type = false
    @is_ast_type_add_children = false
    @is_var_type = false
    @is_enum_type = false
    @is_scope_type = false
    @is_code_gen = false
    @is_decl_type = false
    @const = ''
    @base_namespace = ''

    # Flags
    @need_var_cast = false

    def check_ptr_depth(change_type, ptr_depth)
      !((change_type.es2panda_arg['min_ptr_depth'] && ptr_depth < change_type.es2panda_arg['min_ptr_depth']) ||
      (change_type.es2panda_arg['max_ptr_depth'] && ptr_depth > change_type.es2panda_arg['max_ptr_depth']))
    end

    def delete_ref(type)
      type['ref_depth'] = 0 if type.respond_to?('ref_depth')
    end

    def const
      @const = 'const' if @es2panda_arg['type'].respond_to?('prefix') &&
                          @es2panda_arg['type']['prefix'].include?('const') ||
                          @es2panda_arg['type'].respond_to?('other_modifiers') &&
                          @es2panda_arg['type']['other_modifiers'].include?('const') ||
                          @es2panda_arg['type'].respond_to?('const') &&
                          @es2panda_arg['type']['const'].include?('const')
    end

    def add_const_modifier(args)
      args&.map! do |arg|
        unless arg['type']&.respond_to?('const') && arg['type']&.respond_to?('ptr_depth') &&
               arg['type']&.ptr_depth&.positive?
          arg['type']['const'] = const || ''
        end
        arg
      end
    end

    def add_const_modifier_to_lib_args(const)
      @lib_args&.map! do |arg|
        unless arg['type']&.respond_to?('const') && arg['type']&.respond_to?('ptr_depth') &&
               arg['type']&.ptr_depth&.positive?
          arg['type']['const'] = const
        end
        arg
      end
    end

    def modify_template_nested_arg(arg, base_namespace)
      arg['type'] = ClassData.add_base_namespace(arg['type'], base_namespace)
      tmp = Arg.new(arg, base_namespace)
      raise "Unsupported double+ nested complex types: #{arg_info.to_s}\n" if tmp.lib_args.length > 1
      return nil if tmp.lib_args.nil? || tmp.lib_args[0].nil?

      tmp.lib_args[0]['increase_ptr_depth'] = arg['increase_ptr_depth'] if (arg['increase_ptr_depth'] || 0) != 0
      return tmp.lib_args[0] if tmp.lib_args[0]['type'].nil?

      tmp.lib_args[0]['type']['const'] = tmp.const
      tmp.lib_args[0]
    end

    def unsupported_type_msg()
      ptr_depth = @es2panda_arg['type'].ptr_depth || 0
      "'#{@es2panda_arg['type'].namespace + '::' || ''}"\
      "#{@es2panda_arg['type'].name}"\
      "#{' ' * [1, ptr_depth].min + '*' * (ptr_depth)}'"
    end

    def initialize(arg_info, base_namespace)
      @primitive_types = [
        'char',
        'char16_t',
        'short',
        'int',
        'long',
        'long long',
        'float',
        'double',
        'long double',
        'bool',
        'void',
        'size_t',
        'uint8_t',
        'uint32_t',
        'uint64_t',
        'int8_t',
        'int16_t',
        'int32_t',
        'int64_t',
        'es2panda_Program',
        'es2panda_ExternalSource',
        'es2panda_AstNode',
        'es2panda_FunctionSignature',
        'es2panda_SourcePosition',
        'es2panda_SourceRange',
        'es2panda_SrcDumper',
        'es2panda_AstDumper',
        'es2panda_LabelPair',
        'es2panda_ScriptFunctionData',
        'es2panda_ImportSource',
        'es2panda_Signature',
        'es2panda_SignatureInfo',
        'es2panda_CheckerContext',
        'es2panda_CompilerOptions',
        'es2panda_ResolveResult',
        'es2panda_ValidationInfo',
        'es2panda_Type',
        'es2panda_TypeRelation',
        'es2panda_IndexInfo',
        'es2panda_GlobalTypesHolder',
        'es2panda_ObjectDescriptor',
        'es2panda_Variable',
        'es2panda_Scope',
        'es2panda_Declaration',
        'es2panda_RecordTable',
        'es2panda_AstVisitor',
        'es2panda_CodeGen',
        'es2panda_VReg',
        'NodeTraverser',
        'NodeTransformer',
        'NodePredicate',
        'es2panda_Config',
        'es2panda_Context',
        'PropertyProcessor',
        'PropertyTraverser',
        'ClassBuilder',
        'MethodBuilder',
        'ClassInitializerBuilder',
        'es2panda_variantDoubleCharArrayBool',
        'es2panda_variantIndex',
        'es2panda_DynamicImportData',
        'es2panda_IRNode',
        'es2panda_ScopeFindResult',
        'es2panda_BindingProps',
        'es2panda_BoundContext',
        'es2panda_ErrorLogger',
        'es2panda_ArkTsConfig'
      ]
      @es2panda_arg = arg_info

      @es2panda_arg['const'] = const
      @base_namespace = base_namespace

      found_change_type_link = Es2pandaLibApi.change_types.find do |x|
        x.es2panda_arg.type.respond_to?('name') && x.es2panda_arg.type.name == @es2panda_arg['type']['name'] &&
          (!x.es2panda_arg.type.respond_to?('namespace') ||
            x.es2panda_arg.type.namespace == @es2panda_arg['type'].namespace) &&
          (!x.es2panda_arg.type.respond_to?('current_class') ||
            x.es2panda_arg.type['current_class'] == @es2panda_arg['type']['current_class']) &&
          check_ptr_depth(x, @es2panda_arg['type']['ptr_depth'] || 0)
      end

      unless found_change_type_link
        @is_ast_node = Es2pandaLibApi.ast_nodes.include?(@es2panda_arg['type'].name) &&
                       (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'ir')
        @is_ast_node_add_children = Es2pandaLibApi.ast_node_additional_children.include?(@es2panda_arg['type'].name) &&
                                    (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'ir')
        @is_ast_type = Es2pandaLibApi.ast_types.include?(@es2panda_arg['type'].name) &&
                       (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'checker')
        @is_ast_type_add_children = Es2pandaLibApi.ast_type_additional_children.include?(@es2panda_arg['type'].name) &&
                                    (!@es2panda_arg['type']['namespace'] ||
                                    @es2panda_arg['type']['namespace'] == 'checker')
        @is_var_type = Es2pandaLibApi.ast_variables.any? { |variable| variable[1] == @es2panda_arg['type'].name } &&
                       (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'varbinder')
        @is_enum_type = Es2pandaLibApi.enums.include?(@es2panda_arg['type'].name)
        @is_scope_type = Es2pandaLibApi.scopes.include?(@es2panda_arg['type'].name) &&
                         (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'varbinder')
        @is_decl_type = Es2pandaLibApi.declarations.include?(@es2panda_arg['type'].name) &&
                        (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'varbinder')
        @is_code_gen = Es2pandaLibApi.code_gen_children.include?(@es2panda_arg['type'].name) &&
                       (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'compiler')

        if @is_ast_type
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|AstType|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end

        if @is_ast_type_add_children
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type ==
              '|AstTypeAdditionalChildren|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end

        if @is_ast_node
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|AstNode|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end

        if @is_ast_node_add_children
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type ==
              '|AstNodeAdditionalChildren|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end

        if @is_var_type
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|Variable|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end

        if @is_enum_type
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|Enum|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end

        if @is_scope_type
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|Scope|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end

        if @is_decl_type
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|Declaration|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end

        if @is_code_gen
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|CodeGen|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end
      end

      unless found_change_type_link || @primitive_types.include?(@es2panda_arg['type'].name)
        raise "Unsupported type: #{unsupported_type_msg}"
      end

      ptr_depth = @es2panda_arg['type']['ptr_depth'] || 0

      if found_change_type_link && !check_ptr_depth(found_change_type_link, ptr_depth)
        raise "Invalid ptr depth for type: #{unsupported_type_msg}"
      end

      if found_change_type_link && @es2panda_arg['name'] == 'returnType' &&
         !found_change_type_link.cast.respond_to?('reverse_cast')
         raise "Unsupported return type: #{unsupported_type_msg}"
      end

      if found_change_type_link && @es2panda_arg['name'] == 'callType' &&
         !found_change_type_link.cast.respond_to?('call_cast')
        raise "Unsupported call type: #{unsupported_type_msg}"
      end

      if found_change_type_link && @es2panda_arg['name'] == 'constructorType' &&
         !found_change_type_link.cast.respond_to?('constructor_cast')
        raise "Unsupported constructor type: #{unsupported_type_msg}"
      end

      if found_change_type_link
        found_change_type = Marshal.load(Marshal.dump(found_change_type_link))

        placeholders = find_placeholders(found_change_type.es2panda_arg)

        replacements = placeholders.map do |path, placeholder|
          value = get_value_by_path(@es2panda_arg, path)
          [placeholder, value]
        end

        found_change_type.es2panda_arg = Marshal.load(Marshal.dump(@es2panda_arg))
        found_change_type = deep_replace(found_change_type, replacements)

        clever_replacements = []
        template_args = []

        if found_change_type&.new_args&.length && ((found_change_type.new_args.length > 1 &&
           @es2panda_arg['type'].respond_to?('template_args')) ||
           Es2pandaLibApi.additional_containers.include?(@es2panda_arg['type'].name))
          accessor = (@es2panda_arg['type']['ptr_depth'] || 0).zero? ? '.' : '->'
          clever_replacements += [['|accessor|', accessor]]

          @es2panda_arg['type']['template_args'].each_with_index do |template_arg_raw, i|
            template_arg = Arg.new({ 'name' => @es2panda_arg['name'] + "Element#{i + 1}",
                                     'type' => ClassData.add_base_namespace(template_arg_raw['type'], base_namespace) },
                                   base_namespace)

            raise "Unsupported double+ nested complex types: #{@es2panda_arg.to_s}\n" if template_arg.lib_args.length > 1

            template_arg.add_const_modifier_to_lib_args('const') unless template_arg_raw['type']['const'].nil?

            template_args += [template_arg]
          end

          found_change_type&.new_args&.map! do |arg|
            modify_template_nested_arg(arg, base_namespace)
          end

          found_change_type&.return_args&.map! do |arg|
            modify_template_nested_arg(arg, base_namespace)
          end
          correct_depths(found_change_type)

          template_args.each_with_index do |template_arg, i|
            clever_replacements += [["|template_nested_expression_#{i + 1}|",
                                     if template_arg.lib_cast['expression']
                                       template_arg.lib_cast['expression'] + "\n" else '' end]]
            clever_replacements += [["|reverse_template_nested_expression_#{i + 1}_start|",
                                     template_arg.lib_cast['reverse_cast']&.start&.gsub(
                                       '?const?', template_arg.const || '') || '']]
            clever_replacements += [["|reverse_template_nested_expression_#{i + 1}_end|",
                                     (template_arg.lib_cast['reverse_cast']&.end || '')]]
            unless found_change_type.new_args[i].nil?
              found_change_type.new_args[i]['local_var_name'] = template_arg.lib_cast['var_name']
            end
          end

          @es2panda_arg['type']['ref_depth'] == 2 &&
            found_change_type.cast['var_name'] = 'std::move(' + found_change_type.cast['var_name'] + ')'
        end

        clever_placeholders = find_placeholders(found_change_type)
        clever_replacements += clever_placeholders.map do |_path, placeholder|
          if placeholder.include?('.')
            value = get_placeholder_value(found_change_type, placeholder)
            [placeholder, value]
          else
            is_known_replacement = clever_replacements.any? do |sub_array|
              sub_array[0] =~ /_nested_expression_|\|accessor\|/
            end
            raise "Unknown placeholder: #{placeholder}\n" unless is_known_replacement
          end
        end

        found_change_type = deep_replace(found_change_type, clever_replacements)

        @lib_args = found_change_type&.new_args
        @lib_cast = found_change_type&.cast
        @return_args = found_change_type&.return_args || nil
        nested_arg_transform

      end

      if @lib_args.nil?
        @lib_args = []
        @lib_args << @es2panda_arg if check_allowed_type(@es2panda_arg)
      end

      @lib_args.each do |arg|
        delete_ref(arg['type'])
      end

      if @lib_cast.nil?
        @lib_cast = {}
        @lib_cast['var_name'] = @es2panda_arg['name']
      else
        @need_var_cast = true
      end

      return unless @es2panda_arg['name'] == 'returnType'

      add_const_modifier(@lib_args)
      add_const_modifier(@return_args)
    end

    def check_allowed_type(arg)
      @primitive_types.include?(arg['type'].name) ||
        @is_enum_type || @is_ast_node || @is_ast_node_add_children || @is_ast_type || @is_ast_type_add_children ||
        @is_code_gen || @is_scope_type || @is_var_type
    end

    def nested_arg_transform
      return unless @lib_args && @lib_args.size == 1 && !check_allowed_type(@lib_args[0])

      add_const_modifier(@lib_args)
      tmp = Arg.new(@lib_args[0], @base_namespace)
      @lib_args = tmp.lib_args
      @lib_cast = tmp.lib_cast
      @return_args = tmp.return_args || nil
      nested_arg_transform
    end

    def find_placeholders(data, path = [])
      placeholders = []
      if data.is_a?(OpenStruct)
        data.each_pair do |key, value|
          placeholders += find_placeholders(value, path + [key.to_s])
        end
      elsif data.is_a?(Array)
        data.each_with_index do |value, index|
          placeholders += find_placeholders(value, path + [index])
        end
      elsif data.is_a?(String)
        data.scan(/\|(.+?)\|/) do |match|
          placeholders << [path.join('.'), '|' + match[0] + '|']
        end
      end
      placeholders
    end

    def get_value_by_path(data, path)
      path.split('.').reduce(data) do |current, key|
        current.is_a?(Array) ? current[key.to_i] : current[key]
      end
    end

    def get_placeholder_value(found_change_type, placeholder)
      path_to_value = placeholder.gsub('|', '').gsub('_int', '').gsub(' - 1', '')
      value = get_value_by_path(found_change_type, path_to_value) || 0
      if value.is_a?(Integer)
        if placeholder.end_with?('ptr_depth|')
          value = '*' * value
        elsif placeholder.end_with?('ref_depth|')
          value = '&' * value
        elsif placeholder.end_with?('ptr_depth_int|')
          value = value
        elsif placeholder.end_with?('ptr_depth - 1|')
          value = '*' * (value - 1)
        elsif placeholder.end_with?('namespace|')
          value = ''
        elsif placeholder.end_with?('const|')
          value = ''
        else
          raise "Unknown int found for placeholder '#{placeholder}', value: #{value.to_s}\n"
        end
      end
      value
    end

    # replacements = [[from1, to1], [from2, to2], ...]
    def deep_replace(data, replacements)
      if data.is_a?(OpenStruct)
        data.each_pair do |key, value|
          data[key] = deep_replace(value, replacements)
        end
      elsif data.is_a?(Array)
        data.map! { |value| deep_replace(value, replacements) }
      elsif data.is_a?(String)
        found_replacement = replacements.find { |first, _| first == data }
        if found_replacement
          data = if found_replacement[1].is_a?(String)
                   found_replacement[1]
                 else
                   found_replacement[1].dup
                 end
        else
          replacements.each { |from, to| data.gsub!(from, to) if to.is_a?(String) }
        end
      end
      data
    end

    def correct_depths(data)
      if data.is_a?(OpenStruct)
        if data.respond_to?(:increase_ptr_depth)
          ptr_depth = data.type.ptr_depth || 0
          ptr_depth += data.increase_ptr_depth.to_i
          data.type['ptr_depth'] = ptr_depth
          data.delete_field(:increase_ptr_depth)
        else
          data.each_pair do |key, value|
            data[key] = correct_depths(value)
          end
        end
      elsif data.is_a?(Array)
        data.map! { |value| correct_depths(value) }
      end
      data
    end

    attr_reader :es2panda_arg

    attr_reader :lib_args

    attr_reader :lib_cast

    attr_reader :return_args

    def lib_args_to_str
      @lib_args.map do |lib_arg|
        Arg.arg_to_str(lib_arg)
      end&.join(', ')
    end

    def self.arg_value(arg)
      ptr_depth = arg['type']['ptr_depth'] || 0
      '*' * ptr_depth + arg['name']
    end

    def self.arg_to_str(arg)
      type_to_str(arg['type']) + arg['name']
    end

    def self.type_to_str(type)
      res = type['const'] ? type['const'] + ' ' : ''
      res += type['name']
      ptr_depth = type['ptr_depth'] || 0
      ref_depth = type['ref_depth'] || 0
      res + ' ' + '*' * ptr_depth + '&' * ref_depth
    end

    attr_reader :is_change_type

    def updater_allowed
      @is_ast_node
    end
  end

  class Type
    @raw_type = nil
    @lib_type = nil
    @return_args = nil
    @cast = nil
    @usage = 'no'
    @base_namespace = ''

    def initialize(type_info, base_namespace, usage)
      @raw_type = type_info
      @base_namespace = base_namespace
      @usage = usage
      tmp_arg = Arg.new({ 'name' => "#{usage}Type", 'type' => @raw_type }, base_namespace)

      @return_args = tmp_arg.return_args if tmp_arg.lib_args.length != 1
      unless tmp_arg.lib_args.nil? || tmp_arg.lib_args[0].nil? || tmp_arg.lib_args[0]['type'].nil?
        @lib_type = tmp_arg.lib_args[0]['type']
        remove_unused_const_modifier
      end
      @cast = tmp_arg.lib_cast
    end

    attr_reader :usage

    def remove_unused_const_modifier
      @lib_type['const'] = nil if const && !(@lib_type&.respond_to?('ptr_depth') && @lib_type&.ptr_depth&.positive?)
    end

    def lib_type_to_str
      Arg.type_to_str(@lib_type)
    end

    def arena_item_type
      type = Marshal.load(Marshal.dump(@lib_type))
      type['ptr_depth'] -= 1
      tmp_arg = Arg.new({ 'name' => '', 'type' => type }, @base_namespace)
      Arg.type_to_str(tmp_arg.lib_args[0]['type'])
    end

    def call_cast
      if @cast && usage.include?('call')
        @cast['call_cast']
      else
        ''
      end
    end

    def constructor_cast
      if @cast && usage.include?('constructor')
        @cast['constructor_cast']
      else
        ''
      end
    end

    def cast
      if @cast && @cast && usage.include?('return')
        @cast['reverse_cast']
      else
        ''
      end
    end

    def return_args_to_str
      res = ''
      @return_args&.map do |arg|
        res += ', ' + Arg.arg_to_str(arg)
      end
      res
    end

    def const
      @lib_type['const']
    end

    attr_reader :raw_type
    attr_reader :lib_type
  end

  class ClassData < SimpleDelegator
    @class_base_namespace = ''

    attr_reader :class_base_namespace

    attr_writer :class_base_namespace

    def class_name
      Es2pandaLibApi.classes&.each do |namespace_name, namespace_classes|
        if namespace_classes&.find { |_name, data| data == self }
          return namespace_classes&.find { |_name, data| data == self }[0]
        end
      end
      if Es2pandaLibApi.structs.find { |_name, data| data == self }[0]
        return Es2pandaLibApi.structs.find { |_name, data| data == self }[0]
      end
      raise 'Unknown class name'
    end

    def call_cast
      name = class_name
      class_type = Type.new(add_base_namespace(OpenStruct.new({ 'name' => name, 'ptr_depth' => 1 })),
                            class_base_namespace, 'call')
      class_type.call_cast
    end

    def constructor_type
      name = class_name
      Type.new(add_base_namespace(OpenStruct.new({ 'name' => name, 'ptr_depth' => 1 })), class_base_namespace,
               'constructor')
    end

    def constructor_cast
      name = class_name
      class_type = Type.new(add_base_namespace(OpenStruct.new({ 'name' => name, 'ptr_depth' => 1 })),
                            class_base_namespace, 'constructor')
      class_type.constructor_cast
    end

    def updater_allowed
      name = class_name
      class_arg = Arg.new(OpenStruct.new({ 'name' => 'empty',
                                           'type' =>
                                           add_base_namespace(OpenStruct.new({ 'name' => name, 'ptr_depth' => 1 })) }),
                          class_base_namespace)
      class_arg.updater_allowed
    end

    def usings_map
      dig(:usings)&.map { |using| [using['name'], using['type']] }.to_h || {}
    end

    def check_no_replace_using(_type, new_type)
      res = false
      Es2pandaLibApi.no_usings_replace_info['using types']&.each do |using|
        res ||= Es2pandaLibApi.check_fit(new_type, using)
      end
      !res
    end

    def replace_with_usings(type, usings)
      if usings[type&.name]
        new_type = usings[type.name]
        return type unless check_no_replace_using(type, new_type)

        new_type['ref_depth'] = type['ref_depth'] || 0
        new_type['ptr_depth'] = type['ptr_depth'] || 0
        return new_type
      end
      type
    end

    def add_base_namespace(type)
      ClassData.add_base_namespace(type, class_base_namespace)
    end

    def self.add_base_namespace(type, base_namespace)
      type['namespace'] = base_namespace unless type.respond_to?('namespace') && !type['namespace'].empty?
      type
    end

    def error_catch_log(mode, function, err, func_new_name)
      Es2pandaLibApi.stat_add_unsupported_type(err.message) if err.message.include?('Unsupported type')
      if mode == 'struct_getter'
        Es2pandaLibApi.log('warning', "Error: '#{err.message}'");
        Es2pandaLibApi.log('debug', "Field name: #{function.name}\nField type:\n---\n"\
                                                                "#{function.type.to_s}\n---\n\n")
        Es2pandaLibApi.log('backtrace', err.backtrace.join("\n"), "\n\n")
        Es2pandaLibApi.stat_add_method(0, class_name, class_base_namespace, func_new_name)
        return
      end

      Es2pandaLibApi.log('warning', "#{err.message}\n")
      Es2pandaLibApi.log('debug', "#{mode} name: #{function.name}\n\n"\
                                    "#{mode} raw C++ declaration:\n"\
                                    "```\n#{function.raw_declaration}\n```\n")
      Es2pandaLibApi.log('backtrace', err.backtrace.join("\n"), "\n\n")

      if mode == 'Constructor'
        Es2pandaLibApi.stat_add_constructor(0, class_name, class_base_namespace, func_new_name)
        Es2pandaLibApi.stat_add_class(0, function.name)
      elsif mode == 'Method'
        Es2pandaLibApi.stat_add_method(0, class_name, class_base_namespace, func_new_name)
      else
        raise 'Unreachable'
      end
    end

    def class_constructors
      res = []
      usings = usings_map
      constructor_overload = {}
      dig(:constructors)&.each do |constructor|
        if check_no_gen_constructor(constructor)
          args = []
          begin
            constructor_cast
            constructor.args&.each do |arg|
              arg['type'] = replace_with_usings(arg['type'], usings)
              arg['type'] = add_base_namespace(arg['type'])
              arg['type']['current_class'] = constructor.name
              args << Arg.new(arg, class_base_namespace)
            end
          rescue StandardError => e
            error_catch_log('Constructor', constructor, e, "Create" + class_name)
          else
            Es2pandaLibApi.stat_add_constructor(1, class_name, class_base_namespace, "Create" + class_name)
            Es2pandaLibApi.stat_add_class(1, class_name)

            Es2pandaLibApi.log('info', "Supported constructor for class '#{class_name}'\n")

            res << { 'overload' => get_new_method_name(constructor_overload, '', ''),
            'args' => args, 'raw_decl' => constructor.raw_declaration }
          end
        else
          Es2pandaLibApi.log('info', "Banned constructor for class '#{class_name}'\n")
        end
      end
      res
    end

    def check_no_gen_constructor(constructor)
      res = false
      Es2pandaLibApi.no_gen_constructor_info['postfix_contains']&.each do |postfix|
        res ||= constructor.postfix&.include?(postfix)
      end
      Es2pandaLibApi.no_gen_constructor_info['name_starts_with']&.each do |name_starts_with|
        res ||= constructor.name&.start_with?(name_starts_with)
      end
      constructor.args&.each do |arg|
        Es2pandaLibApi.no_gen_constructor_info['arg_type']&.each do |arg_type|
          res ||= Es2pandaLibApi.check_fit(arg.type, arg_type)
        end
        Es2pandaLibApi.no_gen_method_info['template_type']&.each do |template_type|
          res ||= Es2pandaLibApi.check_fit_template_type(arg.type, template_type)
        end
        Es2pandaLibApi.no_gen_constructor_info['arg_name']&.each do |arg_name|
          res ||= (arg['name'] == arg_name)
        end
      end
      Es2pandaLibApi.no_gen_constructor_info['call_class']&.each do |call_class|
        res ||= (call_class['name'] == class_name)
      end
      !res
    end

    def check_no_gen_method(method)
      res = false # = Will be generated
      Es2pandaLibApi.no_gen_method_info['postfix_contains']&.each do |postfix|
        res ||= method.postfix&.include?(postfix)
      end
      Es2pandaLibApi.no_gen_method_info['name_starts_with']&.each do |name_starts_with|
        res ||= method.name&.start_with?(name_starts_with)
      end
      method.args&.each do |arg|
        Es2pandaLibApi.no_gen_method_info['arg_type']&.each do |arg_type|
          res ||= Es2pandaLibApi.check_fit(arg.type, arg_type)
        end
        Es2pandaLibApi.no_gen_method_info['template_type']&.each do |template_type|
          res ||= Es2pandaLibApi.check_fit_template_type(arg.type, template_type)
        end
        Es2pandaLibApi.no_gen_method_info['arg_name']&.each do |arg_name|
          res ||= (arg['name'] == arg_name)
        end
      end
      Es2pandaLibApi.no_gen_method_info['return_type']&.each do |return_type|
        res ||= begin
                  method.return_type['name'] == return_type['name'] && (!return_type.respond_to?('namespace') ||
        return_type['namespace'] == method.return_type['namespace'])
                end
      end
      Es2pandaLibApi.no_gen_method_info['call_class']&.each do |call_class|
        res ||= (call_class['name'] == class_name)
      end
      Es2pandaLibApi.no_gen_method_info['template_type']&.each do |template_type|
        res ||= Es2pandaLibApi.check_fit_template_type(method.return_type, template_type)
      end
      !res
    end

    def check_no_get_field(field)
      res = false # = Will be generated
      Es2pandaLibApi.no_gen_method_info['name_starts_with']&.each do |name_starts_with|
        res ||= field.name&.start_with?(name_starts_with)
      end
      Es2pandaLibApi.no_gen_method_info['return_type']&.each do |return_type|
        res ||= begin
                  field.type['name'] == return_type['name'] && (!return_type.respond_to?('namespace') ||
        return_type['namespace'] == field.type['namespace'])
                end
      end
      Es2pandaLibApi.no_gen_method_info['call_class']&.each do |call_class|
        res ||= (call_class['name'] == class_name)
      end
      Es2pandaLibApi.no_gen_method_info['template_type']&.each do |template_type|
        res ||= Es2pandaLibApi.check_fit_template_type(field.type, template_type)
      end
      !res
    end

    def get_return_expr(return_type, call_cast, consts, method, args, function_type)
      raise 'Unsupported function type' unless %w[method struct_getter].include?(function_type)
      return_expr = ''
      const, const_return = consts

      if return_type.raw_type['name'] != 'void' && !((return_type.return_args_to_str &&
         !return_type.return_args_to_str.empty?) ||
         Es2pandaLibApi.additional_containers.include?(return_type.raw_type['name']))
        return_expr += 'auto res = '
      end

      return_expr += return_type.cast['start']&.gsub('?const?', const_return) if return_type.cast

      if function_type == 'method'
        return_expr += '(' + call_cast['start']&.gsub('?const?', const) + method['name'] + '('
        return_expr += args&.map do |arg|
          arg.lib_cast['var_name'] if arg.lib_cast
        end&.join(', ')
      elsif function_type == 'struct_getter'
        return_expr += '(' + call_cast['start']&.gsub('?const?', const) + method['name']
      end

      return_expr += ')' + (call_cast['end']&.gsub('?const?', const) || '') + ')'

      return_expr += return_type.cast['end']&.gsub('?const?', const_return) || '' if return_type.cast

      return_expr += if return_type.raw_type['name'] == 'void'
                       ';'
                     else
                       ";\n\treturn res;"
                     end
      return_expr
    end

    def check_for_same_class_name()
      res = false
      class_name_for_check = class_name
      Es2pandaLibApi.classes&.each do |namespace_name, namespace_classes|
        res |= namespace_classes&.find { |_name, data| data != self && _name == class_name_for_check }
      end
      return res
    end

    def get_new_method_name(function_overload, name, const)
      function_name = if check_for_same_class_name then class_base_namespace.capitalize
      else '' end + name + (const != '' ? 'Const' : '')
      overload_name = function_name

      if function_overload.include?(function_name)
        overload_name += function_overload[function_name].to_s
        function_overload[function_name] += 1
      else
        function_overload[function_name] = 1
      end
      overload_name
    end

    def get_const_return_modifier(return_type)
      if return_type&.const && return_type&.const != '' && return_type&.lib_type&.respond_to?('ptr_depth') &&
         return_type&.lib_type&.ptr_depth&.positive?
        'const'
      else
        ''
      end
    end

    def get_const_modifier(method)
      if method.respond_to?('postfix') && method.postfix.include?('const')
        'const'
      else
        ''
      end
    end

    def class_methods
      res = []
      function_overload = {}
      usings = usings_map
      dig(:methods)&.each do |method|
        if check_no_gen_method(method)
          begin
            return_type = Type.new(add_base_namespace(replace_with_usings(method.return_type, usings)),
                                   class_base_namespace, 'return')
            const = get_const_modifier(method)
            const_return = get_const_return_modifier(return_type)

            args = []
            method.args&.each do |arg|
              arg['type'] = add_base_namespace(replace_with_usings(arg['type'], usings))
              args << Arg.new(arg, class_base_namespace)
            end

            return_expr = get_return_expr(return_type, call_cast, [const, const_return], method, args, 'method')
          rescue StandardError => e
            stat_function_overload = Marshal.load(Marshal.dump(function_overload))
            error_catch_log('Method', method, e, class_name +
            get_new_method_name(stat_function_overload, method.name, const))
          else
            stat_function_overload = Marshal.load(Marshal.dump(function_overload))
            Es2pandaLibApi.stat_add_method(1, class_name, class_base_namespace, class_name +
            get_new_method_name(stat_function_overload, method.name, const))
            Es2pandaLibApi.log('info', 'supported method: ', method.name, ' class: ', class_name, "\n")

            res << { 'name' => method.name, 'const' => const, 'return_arg_to_str' => return_type.return_args_to_str,
                     'overload_name' => get_new_method_name(function_overload, method.name, const), 'args' => args,
                     'return_type' => return_type, 'return_expr' => return_expr, 'raw_decl' => method.raw_declaration,
                     'const_return' => const_return }
          end
        else
          Es2pandaLibApi.log('info', "Banned method\n")
        end
      end
      res
    end

    def struct_getters
      res = []
      usings = usings_map
      dig(:members)&.each do |field|
        if check_no_get_field(field)
          begin
            return_type = Type.new(add_base_namespace(replace_with_usings(field.type, usings)),
                                   class_base_namespace, 'return')
            const = ''
            const_return = get_const_return_modifier(return_type)

            return_expr = get_return_expr(return_type, call_cast, [const, const_return], field, nil, 'struct_getter')
          rescue StandardError => e
            error_catch_log('struct_getter', field, e, class_name + field.name)
          else
            Es2pandaLibApi.stat_add_method(1, class_name, class_base_namespace, class_name + field.name)
            Es2pandaLibApi.log('info', 'supported struct getter: ', field.name, ' struct: ', class_name, "\n")

            res << { 'name' => field.name, 'return_arg_to_str' => return_type.return_args_to_str,
                     'return_type' => return_type, 'return_expr' => return_expr, 'const_return' => const_return }
          end
        else
          Es2pandaLibApi.log('info', "Banned method\n")
        end
      end
      res
    end
  end

  @ast_nodes = Set.new(%w[AstNode Expression Statement TypeNode])
  @ast_types = Set.new(['Type'])
  @scopes = Set.new(%w[Scope VariableScope])
  @declarations = Set.new(['Decl'])
  @classes = {}
  @structs = {}
  @includes = Set.new
  @change_types = []
  @enums = Set.new(%w[AstNodeType ScopeType DeclType])

  @all_methods = 0.0
  @all_constructors = 0.0
  @all_classes = Set.new
  @classes_with_supported_constructor = Set.new
  @unsupported_types = {}

  @supported_methods = 0.0
  @supported_method_type = {}
  @supported_constructors = 0.0
  @supported_constructor_type = {}

  @info_log = false
  @debug_log = false
  @warning_log = true
  @backtrace_log = false
  @stat_log = false
  @type_stat_log = false

  def log(debug_level, *args)

    if debug_level == 'info' && @info_log
      print args.join('').to_s
    elsif debug_level == 'debug' && @debug_log
      print args.join('').to_s
    elsif debug_level == 'warning' && @warning_log
      print "WARNING:[e2p_api_generator]: #{args.join('').to_s}"
    elsif debug_level == 'backtrace' && @backtrace_log
      print args.join('').to_s
    elsif debug_level == 'stat' && @stat_log
      print args.join('').to_s
    elsif debug_level == 'type_stat' && @type_stat_log
      print args.join('').to_s
    end
  end

  def no_usings_replace_info
    { 'using types' => [
      { 'name' => 'function', 'namespace' => 'std' }
    ] }
  end

  def no_gen_constructor_info
    { 'name_starts_with' =>
      [],
      'postfix_contains' =>
      ['= delete', 'override'],
      'arg_type' =>
      [{ 'name' => 'Tag' }, { 'name' => 'T' }, { 'name' => 'K' },
       { 'name' => 'Number', 'namespace' => 'lexer' }, { 'name' => 'ModuleEntry', 'namespace' => 'varbinder' },
       { 'name' => 'Property', 'namespace' => 'AstDumper' },
       { 'name' => 'TSChecker', 'namespace' => 'checker' }, { 'name' => 'RelationHolder', 'namespace' => 'checker' },
       { 'name' => 'initializer_list' }, { 'name' => 'stringstream' }, { 'name' => 'Holder' }, { 'name' => 'tuple' },
       { 'name' => 'UnaryPredicate', 'namespace' => 'checker' }, { 'name' => 'ScopedDebugInfoPlugin' },
       { 'name' => 'ModulesToExportedNamesWithAliases', 'namespace' => 'varbinder' }, { 'name' => 'SmartCastTypes' },
       { 'name' => 'VariableType', 'namespace' => 'varbinder' }, { 'name' => 'Args', 'namespace' => 'varbinder' },
       { 'name' => 'InsertResult', 'namespace' => 'varbinder' }, { 'name' => 'auto' }, { 'name' => 'recursive_mutex' },
       { 'name' => 'ConstraintCheckRecord' }, { 'name' => 'optional', 'namespace' => 'std' },
       { 'name' => 'WrapperDesc' }, { 'name' => 'Args', 'namespace' => 'parser' }],
      'template_type' =>
      [{ 'name' => 'Checker' }, { 'name' => 'ETSChecker' }, { 'name' => 'Program' }, { 'name' => 'stringstream' },
       { 'name' => 'TSChecker', 'namespace' => 'checker' }, { 'name' => 'T' }, { 'name' => 'K' }, { 'name' => 'tuple' },
       { 'name' => 'ModuleEntry', 'namespace' => 'varbinder' }, { 'name' => 'Args' },
       { 'name' => 'ETSBinder' }, { 'name' => 'InsertResult', 'namespace' => 'varbinder' }, { 'name' => 'pair' },
       { 'name' => 'SmartCastTypes' }, { 'name' => 'ConstraintCheckRecord' }, { 'name' => 'ArenaVector' },
       { 'name' => 'optional', 'namespace' => 'std' }, { 'name' => 'ScopedDebugInfoPlugin' }],
      'call_class' =>
      [{ 'name' => 'AstNode' }, { 'name' => 'ClassElement' }, { 'name' => 'TypedStatement' }, { 'name' => 'Annotated' },
       { 'name' => 'Scope' }, { 'name' => 'Type' }, { 'name' => 'ObjectType' }, { 'name' => 'VarBinder' },
       { 'name' => 'ETSBinder' }, { 'name' => 'BoundContext', 'namespace' => 'varbinder' },
       { 'name' => 'Checker' }, { 'name' => 'ETSChecker' }, { 'name' => 'ETSParser' }],
      'arg_name' =>
      ['[N]'] }
  end

  def no_gen_method_info
    { 'name_starts_with' =>
      ['~', 'HasFloatingPoint', 'AddChildLambda', 'operator=', 'NumericConditionalCheck', 'CompileComputed',
       'Result', 'GetConstOriginalBaseType', 'GetOwnProperty', 'AddProperty', 'RemoveProperty', 'ReduceSubtypes',
       'CheckIdenticalVariable', 'CreatePropertyMap', 'AddSpecifiersToTopBindings', 'CheckForRedeclarationError',
       'CheckExpressionsInConstructor', 'PerformArithmeticOperationOnTypes', 'PerformRelationOperationOnTypes',
       'BindingsModuleObjectAddProperty', 'MakePropertyNonNullish', 'GetProxyMethodBody', 'GetFlagsForProxyLambda',
       'ComputeProxyMethods', 'CheckValidUnionEqual', 'TestUnionType', 'IsValidSetterLeftSide', 'CreateProxyFunc',
       'ApplyModifiersAndRemoveImplementedAbstracts', 'ValidateAbstractSignature', 'ValidateNonOverriddenFunction',
       'InvalidateType', 'TypeError'],
      'postfix_contains' =>
      ['= delete', 'override'],
      'return_type' =>
      [{ 'name' => 'Checker' }, { 'name' => 'ETSChecker' }, { 'name' => 'ArenaAllocator' },
       { 'name' => 'Allocator' }, { 'name' => 'Program' }, { 'name' => 'Tag' }, { 'name' => 'ConstraintCheckRecord' },
       { 'name' => 'Number', 'namespace' => 'lexer' }, { 'name' => 'Property', 'namespace' => 'AstDumper' },
       { 'name' => 'TSChecker', 'namespace' => 'checker' }, { 'name' => 'stringstream' }, { 'name' => 'Holder' },
       { 'name' => 'tuple' }, { 'name' => 'UnaryPredicate', 'namespace' => 'checker' }, { 'name' => 'VarBinder' },
       { 'name' => 'ModulesToExportedNamesWithAliases', 'namespace' => 'varbinder' }, { 'name' => 'T' },
       { 'name' => 'K' }, { 'name' => 'ModuleEntry', 'namespace' => 'varbinder' }, { 'name' => 'ETSBinder' },
       { 'name' => 'Context', 'namespace' => 'public_lib' }, { 'name' => 'VariableType', 'namespace' => 'varbinder' },
       { 'name' => 'Args', 'namespace' => 'varbinder' }, { 'name' => 'InsertResult', 'namespace' => 'varbinder' },
       { 'name' => 'RelationHolder', 'namespace' => 'checker' }, { 'name' => 'auto' }, { 'name' => 'recursive_mutex' },
       { 'name' => 'SmartCastArray' }, { 'name' => 'SmartCastTypes' }, { 'name' => 'SemanticAnalyzer' },
       { 'name' => 'optional', 'namespace' => 'std' }, { 'name' => 'WrapperDesc' }, { 'name' => 'Language' },
       { 'name' => 'ScopedDebugInfoPlugin' }, { 'name' => 'Args', 'namespace' => 'parser' }, { 'name' => 'ETSParser' }],
      'arg_type' =>
      [{ 'name' => 'Tag' }, { 'name' => 'Number', 'namespace' => 'lexer' }, { 'name' => 'K' },
       { 'name' => 'Property', 'namespace' => 'AstDumper' }, { 'name' => 'TSChecker', 'namespace' => 'checker' },
       { 'name' => 'ArenaVector', 'template_args' => [{ 'type' => { 'name' => 'pair' } }] },
       { 'name' => 'initializer_list' }, { 'name' => 'stringstream' }, { 'name' => 'Holder' }, { 'name' => 'tuple' },
       { 'name' => 'UnaryPredicate', 'namespace' => 'checker' }, { 'name' => 'ScopedDebugInfoPlugin' },
       { 'name' => 'ModulesToExportedNamesWithAliases', 'namespace' => 'varbinder' }, { 'name' => 'T' },
       { 'name' => 'ModuleEntry', 'namespace' => 'varbinder' }, { 'name' => 'Args', 'namespace' => 'varbinder' },
       { 'name' => 'VariableType', 'namespace' => 'varbinder' }, { 'name' => 'Span' }, { 'name' => 'recursive_mutex' },
       { 'name' => 'InsertResult', 'namespace' => 'varbinder' }, { 'name' => 'auto' }, { 'name' => 'SmartCastArray' },
       { 'name' => 'SmartCastTypes' }, { 'name' => 'ConstraintCheckRecord' }, { 'name' => 'WrapperDesc' },
       { 'name' => 'optional', 'namespace' => 'std' }, { 'name' => 'RelationHolder', 'namespace' => 'checker' },
       { 'name' => 'Args', 'namespace' => 'parser' }],
      'template_type' =>
      [{ 'name' => 'Checker' }, { 'name' => 'ETSChecker' }, { 'name' => 'Program' }, { 'name' => 'stringstream' },
       { 'name' => 'TSChecker', 'namespace' => 'checker' }, { 'name' => 'T' }, { 'name' => 'K' },
       { 'name' => 'ModuleEntry', 'namespace' => 'varbinder' }, { 'name' => 'Args' },
       { 'name' => 'ETSBinder' }, { 'name' => 'InsertResult', 'namespace' => 'varbinder' }, { 'name' => 'pair' },
       { 'name' => 'RelationHolder', 'namespace' => 'checker' }, { 'name' => 'recursive_mutex' }, { 'name' => 'tuple' },
       { 'name' => 'SmartCastArray' }, { 'name' => 'SmartCastTypes' }, { 'name' => 'ConstraintCheckRecord' },
       { 'name' => 'optional', 'namespace' => 'std' }, { 'name' => 'ArenaVector' }, { 'name' => 'WrapperDesc' },
       { 'name' => 'ScopedDebugInfoPlugin' }],
      'call_class' =>
      [{ 'name' => 'Annotated' }],
      'arg_name' =>
      ['[N]'] }
  end

  def check_fit(data, pattern)
    return true if data.nil? || pattern.nil?

    if pattern.is_a?(OpenStruct) || pattern.is_a?(Hash)
      pattern.each_pair do |key, value|
        return false unless check_fit(data[key], value)
      end
    elsif pattern.is_a?(Array)
      pattern.each_with_index do |value, i|
        return false unless check_fit(data[i], value)
      end
    elsif pattern.is_a?(String) || pattern.is_a?(Integer)
      return false if data != pattern
    end

    true
  end

  def check_fit_template_type(type, template_pattern)
    res = false
    if type.respond_to?('template_args')
      type['template_args']&.each do |template_arg|
        next if template_arg['type'].nil?

        res ||= Es2pandaLibApi.check_fit(template_arg['type'], template_pattern)
        res ||= Es2pandaLibApi.check_fit_template_type(template_arg['type'], template_pattern)
      end
    end
    res
  end

  def check_class_type(class_name, class_base_namespace)
    type = ''
    if ast_nodes.include?(class_name) && class_base_namespace == "ir"
      type = "AST manipulation"
    elsif ast_node_additional_children.include?(class_name) && class_base_namespace == "ir"
      type = "AST manipulation"
    elsif class_base_namespace == "ir"
      type = "AST manipulation"
    elsif ast_types.include?(class_name) && class_base_namespace == "checker"
      type = "Type manipulation"
    elsif ast_type_additional_children.include?(class_name) && class_base_namespace == "checker"
      type = "Type manipulation"
    elsif class_base_namespace == "checker"
      type = "Type check"
    elsif ast_variables.find { |x| x[1] == class_name } && class_base_namespace == "varbinder"
      type = "Variable manipulation"
    elsif scopes.include?(class_name) && class_base_namespace == "varbinder"
      type = "Scope manipulation"
    elsif declarations.include?(class_name) && class_base_namespace == "varbinder"
      type = "Declaration"
    elsif class_base_namespace == "varbinder"
      type = "Varbinder manipulation"
    elsif class_base_namespace == "parser"
      type = "Parser manipulation"
    elsif class_base_namespace == "es2panda"
      type = "Getters for compiler options"
    else
      raise "Unsupported class type for stats class name: \"" +
      class_name + "\" class namespace: \"" + class_base_namespace + "\""
    end
    type
  end

  def stat_add_method_type(class_name, class_base_namespace, func_new_name)
    type = check_class_type(class_name, class_base_namespace)
    if @supported_method_type[type]
      @supported_method_type[type][0] += 1
      @supported_method_type[type][1] << func_new_name
    else
      @supported_method_type[type] = [1, [func_new_name]]
    end
  end

  def stat_add_constructor_type(class_name, class_base_namespace, constructor_new_name)
    type = check_class_type(class_name, class_base_namespace)
    if @supported_constructor_type[type]
      @supported_constructor_type[type][0] += 1
      @supported_constructor_type[type][1] << constructor_new_name
    else
      @supported_constructor_type[type] = [1, [constructor_new_name]]
    end
  end

  def stat_add_method(support, class_name, class_base_namespace, func_new_name)
    @all_methods += 1
    @supported_methods += support
    if support == 1
      stat_add_method_type(class_name, class_base_namespace, func_new_name)
    end
  end

  def stat_add_constructor(support, class_name, class_base_namespace, constructor_new_name)
    @all_constructors += 1
    @supported_constructors += support
    if support == 1
      stat_add_constructor_type(class_name, class_base_namespace, constructor_new_name)
    end
  end

  def stat_add_class(support, class_name)
    @all_classes << class_name
    @classes_with_supported_constructor << class_name if support != 0
  end

  def stat_add_unsupported_type(err_msg)
    @unsupported_types[err_msg] ||= 0
    @unsupported_types[err_msg] += 1
  end

  def print_stats
    Es2pandaLibApi.log('stat',
    "--------------\n"\
    "Es2panda API generated:\n"\
    " - Methods: #{@supported_methods} / #{@all_methods} ( #{(@supported_methods / @all_methods * 100).round(2)} % )\n"\
    " - Constructors: #{@supported_constructors} / #{@all_constructors} ( "\
    "#{(@supported_constructors / @all_constructors * 100).round(2)} % )\n"\
    " - Classes: #{@classes_with_supported_constructor.size} / #{@all_classes.size} ( "\
    "#{(@classes_with_supported_constructor.size.to_f / @all_classes.size * 100).round(2)} % )\n"\
    "--------------\n"
    )
  end

  def ast_nodes
    @ast_nodes
  end

  def ast_types
    @ast_types
  end

  def scopes
    @scopes
  end

  def declarations
    @declarations
  end

  def ast_variables
    [%w[NO Variable],
     %w[LOCAL LocalVariable],
     %w[GLOBAL GlobalVariable],
     %w[MODULE ModuleVariable],
     %w[ENUM EnumVariable]]
  end

  def ast_type_additional_children
    %w[
      ETSStringType
      ETSDynamicType
      ETSAsyncFuncReturnType
      ETSDynamicFunctionType
      ETSEnumType
      ETSBigIntType
    ]
  end

  def additional_containers
    %w[
      shared_ptr
    ]
  end

  def additional_classes_to_generate
    %w[
      TypeRelation
      GlobalTypesHolder
      Checker
      ETSChecker
      CheckerContext
      ResolveResult
      SignatureInfo
      Signature
      VarBinder
      ETSBinder
      RecordTable
      BoundContext
      ETSParser
    ]
  end

  def structs_to_generate
    %w[
      CompilerOptions
    ]
  end

  def ast_node_additional_children
    %w[
      TypedStatement
      ClassElement
      AnnotatedExpression
      Literal
      LoopStatement
      MaybeOptionalExpression
      Property
    ]
  end

  def code_gen_children
    %w[
      CodeGen
      PandaGen
      ETSGen
    ]
  end

  def classes
    @classes
  end

  def structs
    @structs
  end

  def includes
    @includes
  end

  def change_types
    @change_types
  end

  def enums
    @enums
  end

  def wrap_data(data)
    return unless data

    data.macros&.each do |macros|
      case macros.name
      when 'AST_NODE_MAPPING'
        @ast_nodes.merge(Set.new(macros.values&.map { |x| x[1] }))
      when 'AST_NODE_REINTERPRET_MAPPING'
        @ast_nodes.merge(Set.new(macros.values&.map { |x| x[2..3] }&.flatten))
      when 'TYPE_MAPPING'
        @ast_types.merge(Set.new(macros.values&.map { |x| x[1] }&.flatten))
      end
    end

    data.varbinder&.macros&.each do |macros|
      case macros.name
      when 'SCOPE_TYPES'
        @scopes.merge(Set.new(macros.values&.map { |x| x[1] }))
      when 'DECLARATION_KINDS'
        @declarations.merge(Set.new(macros.values&.map { |x| x[1] }))
      end
    end

    data.ast_node_reinterpret_mapping&.each do |mapping|
      @ast_nodes << mapping[2]
      @ast_nodes << mapping[3]
    end

    data.paths&.each do |include|
      @includes << include
    end

    data.change_types&.each do |change_type|
      @change_types << change_type
    end

    @classes['ir'] = {} unless @classes['ir']
    data['ir']&.class_definitions&.each do |class_definition|
      @classes['ir'][class_definition.name] = ClassData.new(class_definition&.public)
      @classes['ir'][class_definition.name].class_base_namespace = 'ir'
    end

    @classes['checker'] = {} unless @classes['checker']
    data['checker']&.class_definitions&.each do |class_definition|
      if @ast_types.include?(class_definition.name) || ast_type_additional_children.include?(class_definition.name) ||
         additional_classes_to_generate.include?(class_definition.name)
        @classes['checker'][class_definition.name] = ClassData.new(class_definition&.public)
        @classes['checker'][class_definition.name].class_base_namespace = 'checker'
      end
    end

    @classes['varbinder'] = {} unless @classes['varbinder']
    data['varbinder']&.class_definitions&.each do |class_definition|
      if scopes.include?(class_definition.name) || declarations.include?(class_definition.name) ||
         ast_variables.find { |x| x[1] == class_definition.name } ||
         additional_classes_to_generate.include?(class_definition.name)
        @classes['varbinder'][class_definition.name] = ClassData.new(class_definition&.public)
        @classes['varbinder'][class_definition.name].class_base_namespace = 'varbinder'
      end
    end

    @classes['parser'] = {} unless @classes['parser']
    data['parser']&.class_definitions&.each do |class_definition|
      if additional_classes_to_generate.include?(class_definition.name)
        @classes['parser'][class_definition.name] = ClassData.new(class_definition&.public)
        @classes['parser'][class_definition.name].class_base_namespace = 'parser'
      end
    end

    data['es2panda']&.structs&.each do |struct|
      if structs_to_generate.include?(struct.name)
        @structs[struct.name] = ClassData.new(struct)
        @structs[struct.name].class_base_namespace = 'es2panda'
      end
    end

    data.enums&.each do |enum|
      @enums << enum.name
    end

    Enums.wrap_data(data)
  end

  module_function :wrap_data, :classes, :ast_nodes, :includes, :change_types, :enums, :ast_types, :check_fit, :log,
                  :stat_add_constructor, :stat_add_method, :print_stats, :no_gen_method_info, :no_gen_constructor_info,
                  :stat_add_class, :stat_add_unsupported_type, :ast_node_additional_children, :code_gen_children,
                  :additional_classes_to_generate, :ast_type_additional_children, :scopes, :ast_variables,
                  :no_usings_replace_info, :declarations, :check_fit_template_type, :structs, :structs_to_generate,
                  :additional_containers, :stat_add_constructor_type, :stat_add_method_type, :check_class_type
end

def Gen.on_require(data)
  Es2pandaLibApi.wrap_data(data)
end
