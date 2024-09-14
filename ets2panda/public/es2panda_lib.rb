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
    @is_var_type = false
    @is_enum_type = false
    @is_scope_type = false
    @is_code_gen = false

    # Flags
    @need_var_cast = false

    def check_ptr_depth(change_type, ptr_depth)
      !((change_type.es2panda_arg['min_ptr_depth'] && ptr_depth < change_type.es2panda_arg['min_ptr_depth']) ||
      (change_type.es2panda_arg['max_ptr_depth'] && ptr_depth > change_type.es2panda_arg['max_ptr_depth']))
    end

    def delete_ref(type)
      type['ref_depth'] = 0 if type.respond_to?('ref_depth')
    end

    def initialize(arg_info)
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
        'uint32_t',
        'int32_t',
        'int64_t',
        'es2panda_AstNode',
        'es2panda_Type',
        'es2panda_Scope'
      ]
      @es2panda_arg = arg_info

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
        @is_var_type = Es2pandaLibApi.ast_variables.any? { |variable| variable[1] == @es2panda_arg['type'].name } &&
                       (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'varbinder')
        @is_enum_type = Es2pandaLibApi.enums.include?(@es2panda_arg['type'].name)
        @is_scope_type = Es2pandaLibApi.scopes.include?(@es2panda_arg['type'].name) &&
                         (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'varbinder')
        @is_code_gen = Es2pandaLibApi.code_gen_children.include?(@es2panda_arg['type'].name) &&
                       (!@es2panda_arg['type']['namespace'] || @es2panda_arg['type']['namespace'] == 'compiler')

        if @is_ast_type
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|AstType|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
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

        if @is_code_gen
          found_change_type_link = Es2pandaLibApi.change_types.find do |x|
            x.es2panda_arg.type == '|CodeGen|' && check_ptr_depth(x, @es2panda_arg['type'].ptr_depth || 0)
          end
        end
      end

      unless found_change_type_link || @primitive_types.include?(@es2panda_arg['type'].name)
        raise "Unsupported type: '" + @es2panda_arg['type'].name + "' ptr depth: " +
              (@es2panda_arg['type'].ptr_depth || 0).to_s
      end

      ptr_depth = @es2panda_arg['type']['ptr_depth'] || 0

      if found_change_type_link && !check_ptr_depth(found_change_type_link, ptr_depth)
        raise 'invalid ptr_depth: ' + ptr_depth.to_s + ', type: ' + @es2panda_arg['type'].name
      end

      if found_change_type_link && @es2panda_arg['name'] == 'returnType' &&
         !found_change_type_link.cast.respond_to?('reverse_cast')
        raise 'Unsupported return type: ' + @es2panda_arg['type'].name + ' ptr depth: ' +
              (@es2panda_arg['type'].ptr_depth || 0).to_s
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

        if found_change_type&.new_args&.length && found_change_type.new_args.length > 1 &&
           @es2panda_arg['type'].respond_to?('template_args')
          accessor = (@es2panda_arg['type']['ptr_depth'] || 0).zero? ? '.' : '->'
          clever_replacements += [['|accessor|', accessor]]

          @es2panda_arg['type']['template_args'].each_with_index do |template_arg_raw, i|
            template_arg = Arg.new({ 'name' => @es2panda_arg['name'] + "Element#{i + 1}",
                                     'type' => template_arg_raw['type'] })
            raise 'Unsupported double+ nested complex types: ' + @es2panda_arg.to_s if template_arg.lib_args.length > 1

            template_args += [template_arg]
          end

          found_change_type&.new_args&.map! do |arg|
            tmp = Arg.new(arg)
            raise 'Unsupported double+ nested complex types: ' + arg_info.to_s if tmp.lib_args.length > 1

            tmp.lib_args[0]['increase_ptr_depth'] = arg['increase_ptr_depth'] if (arg['increase_ptr_depth'] || 0) != 0
            tmp.lib_args[0]
          end

          found_change_type&.return_args&.map! do |arg|
            tmp = Arg.new(arg)
            raise 'Unsupported double+ nested complex types: ' + arg_info if tmp.lib_args.length > 1

            tmp.lib_args[0]['increase_ptr_depth'] = arg['increase_ptr_depth'] if (arg['increase_ptr_depth'] || 0) != 0
            tmp.lib_args[0]
          end
          correct_depths(found_change_type)

          template_args.each_with_index do |template_arg, i|
            clever_replacements += [["|template_nested_expression_#{i + 1}|",
                                     template_arg.lib_cast['expression'] + "\n"]]
            clever_replacements += [["|reverse_template_nested_expression_#{i + 1}_start|",
                                     template_arg.lib_cast['reverse_cast']&.start&.gsub('?const?', '') || '']]
            clever_replacements += [["|reverse_template_nested_expression_#{i + 1}_end|",
                                     (template_arg.lib_cast['reverse_cast']&.end || '')]]
            found_change_type.new_args[i]['local_var_name'] = template_arg.lib_cast['var_name']
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
            raise 'Unknown placeholder: ' + placeholder + "\n" unless is_known_replacement
          end
        end

        found_change_type = deep_replace(found_change_type, clever_replacements)

        @lib_args = found_change_type&.new_args
        @lib_cast = found_change_type&.cast
        @return_args = found_change_type&.return_args || nil

      end

      if @lib_args.nil?
        @lib_args = []
        @lib_args << @es2panda_arg
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
        else
          raise 'Unknown integer found for placeholer: ' + placeholder + ', res: ' + value.to_s + "\n"
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
      res = type['name']
      ptr_depth = type['ptr_depth'] || 0
      ref_depth = type['ref_depth'] || 0
      res + ' ' + '*' * ptr_depth + '&' * ref_depth
    end

    attr_reader :is_change_type

    def updater_allowed
      @is_ast_type || @is_ast_node || @is_ast_node_add_children || @is_var_type || @is_enum_type ||
        @is_scope_type || @is_code_gen
    end
  end

  class Type
    @raw_type = nil
    @lib_type = nil
    @return_args = nil
    @cast = nil

    def initialize(type_info)
      @raw_type = type_info
      tmp_arg = Arg.new({ 'name' => 'returnType', 'type' => @raw_type })

      @return_args = tmp_arg.return_args if tmp_arg.lib_args.length != 1
      @lib_type = tmp_arg.lib_args[0]['type']
      @cast = tmp_arg.lib_cast
    end

    def lib_type_to_str
      Arg.type_to_str(@lib_type)
    end

    def arena_item_type
      type = Marshal.load(Marshal.dump(@lib_type))
      type['ptr_depth'] -= 1
      tmp_arg = Arg.new({ 'name' => '', 'type' => type })
      Arg.type_to_str(tmp_arg.lib_args[0]['type'])
    end

    def call_cast
      if @cast
        @cast['call_cast']
      else
        ''
      end
    end

    def constructor_cast
      if @cast
        @cast['constructor_cast']
      else
        ''
      end
    end

    def cast
      if @cast
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

    attr_reader :raw_type
    attr_reader :lib_type
  end

  class ClassData < SimpleDelegator
    def class_name
      Es2pandaLibApi.classes.find { |_name, data| data == self }[0]
    end

    def call_cast
      name = class_name
      class_type = Type.new(OpenStruct.new({ 'name' => name, 'ptr_depth' => 1 }))
      class_type.call_cast
    end

    def constructor_type
      name = class_name
      Type.new(OpenStruct.new({ 'name' => name, 'ptr_depth' => 1 }))
    end

    def constructor_cast
      name = class_name
      class_type = Type.new(OpenStruct.new({ 'name' => name, 'ptr_depth' => 1 }))
      class_type.constructor_cast
    end

    def updater_allowed
      name = class_name
      class_arg = Arg.new(OpenStruct.new({ 'name' => 'empty',
                                           'type' => OpenStruct.new({ 'name' => name, 'ptr_depth' => 1 }) }))
      class_arg.updater_allowed
    end

    def usings_map
      dig(:usings)&.map { |using| [using['name'], using['type']] }.to_h || {}
    end

    def replace_with_usings(type, usings)
      if usings[type&.name]
        new_type = usings[type.name]
        new_type['ref_depth'] = type['ref_depth'] || 0
        new_type['ptr_depth'] = type['ptr_depth'] || 0
        return new_type
      end
      type
    end

    def error_catch_log(mode, function, err)
      if mode == 'constructor'
        Es2pandaLibApi.log('error', "Error: '#{err.message}'\nConstructor: #{function.name}\nRaw:\n---\n"\
                                                                          "#{function.raw_declaration}\n---\n\n")
        Es2pandaLibApi.log('backtrace', err.backtrace.join("\n"), "\n")
        Es2pandaLibApi.stat_add_unsupported_type(err.message) if err.message.include?('Unsupported type')
        Es2pandaLibApi.stat_add_constructor(0)
        Es2pandaLibApi.stat_add_class(0, function.name)
      elsif mode == 'method'
        Es2pandaLibApi.log('error', "Error: '#{err.message}'\nClass: #{function.name}\nRaw:\n---\n"\
                                                                    "#{function.raw_declaration}\n---\n\n")
        Es2pandaLibApi.log('backtrace', err.backtrace.join("\n"), "\n\n")
        Es2pandaLibApi.stat_add_unsupported_type(err.message) if err.message.include?('Unsupported type')
        Es2pandaLibApi.stat_add_method(0)
      else
        raise 'Unreachable'
      end
    end

    def class_constructors
      res = []
      usings = usings_map
      dig(:constructors)&.each do |constructor|
        if check_no_gen_constructor(constructor)
          args = []
          begin
            constructor_cast
            constructor.args&.each do |arg|
              arg['type'] = replace_with_usings(arg['type'], usings)
              arg['type']['current_class'] = constructor.name
              args << Arg.new(arg)
            end
          rescue StandardError => e
            error_catch_log('constructor', constructor, e)
          else
            Es2pandaLibApi.stat_add_constructor(1)
            Es2pandaLibApi.stat_add_class(1, class_name)

            Es2pandaLibApi.log('info', "Supported constructor for class '#{class_name}'\n")

            res << { 'args' => args, 'raw_decl' => constructor.raw_declaration }
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
      Es2pandaLibApi.no_gen_constructor_info['arg_type']&.each do |arg_type|
        constructor.args&.each do |arg|
          res ||= Es2pandaLibApi.check_fit(arg.type, arg_type)
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
      Es2pandaLibApi.no_gen_method_info['arg_type']&.each do |arg_type|
        method.args&.each do |arg|
          res ||= Es2pandaLibApi.check_fit(arg.type, arg_type)
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
      !res
    end

    def get_return_expr(return_type, call_cast, const, method, args)
      return_expr = ''

      if return_type.raw_type['name'] != 'void' && return_type.raw_type['name'] != 'ArenaVector' &&
         return_type.raw_type['name'] != 'ArenaSet' && return_type.raw_type['name'] != 'pair' &&
         return_type.raw_type['name'] != 'vector'
        return_expr += 'auto res = '
      end

      return_expr += return_type.cast['start']&.gsub('?const?', const) if return_type.cast

      return_expr += '(' + call_cast['start']&.gsub('?const?', const) + method['name'] + '('
      return_expr += args&.map do |arg|
        arg.lib_cast['var_name'] if arg.lib_cast
      end&.join(', ')
      return_expr += ')' + (call_cast['end']&.gsub('?const?', const) || '') + ')'

      return_expr += return_type.cast['end'] || '' if return_type.cast

      return_expr += if return_type.raw_type['name'] == 'void'
                       ';'
                     elsif const == ''
                       ";\n\treturn res;"
                     else
                       ";\n\treturn const_cast<const " + return_type.lib_type_to_str + '>(res);'
                     end
      return_expr
    end

    def get_new_method_name(function_overload, name, const)
      function_name = name + (const != '' ? 'Const' : '')
      overload_name = function_name

      if function_overload.include?(function_name)
        overload_name += function_overload[function_name].to_s
        function_overload[function_name] += 1
      else
        function_overload[function_name] = 1
      end
      overload_name
    end

    def get_const_modifier(return_type)
      if return_type&.raw_type&.prefix&.include?('const') && return_type&.lib_type&.respond_to?('ptr_depth') &&
         return_type&.lib_type&.ptr_depth&.positive?
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
            return_type = Type.new(replace_with_usings(method.return_type, usings))
            const = get_const_modifier(return_type)

            args = []
            method.args&.each do |arg|
              arg['type'] = replace_with_usings(arg['type'], usings)
              args << Arg.new(arg)
            end

            return_expr = get_return_expr(return_type, call_cast, const, method, args)
          rescue StandardError => e
            error_catch_log('method', method, e)
          else
            Es2pandaLibApi.stat_add_method(1)
            Es2pandaLibApi.log('info', 'supported method: ', method.name, ' class: ', class_name, "\n")

            res << { 'name' => method.name, 'const' => const, 'return_arg_to_str' => return_type.return_args_to_str,
                     'overload_name' => get_new_method_name(function_overload, method.name, const), 'args' => args,
                     'return_type' => return_type, 'return_expr' => return_expr, 'raw_decl' => method.raw_declaration }
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
  @scopes = Set.new(['Scope'])
  @classes = {}
  @includes = Set.new
  @change_types = []
  @enums = Set.new(['AstNodeType'])

  @all_methods = 0.0
  @all_constructors = 0.0
  @all_classes = Set.new
  @classes_with_supported_constructor = Set.new
  @unsupported_types = {}

  @supported_methods = 0.0
  @supported_constructors = 0.0

  def log(debug_level, *args)
    info_log = false
    debug_log = false
    error_log = true
    backtrace_log = true
    stat_log = true

    if debug_level == 'info' && info_log
      print args.join('').to_s
    elsif debug_level == 'debug' && debug_log
      print args.join('').to_s
    elsif debug_level == 'error' && error_log
      print args.join('').to_s
    elsif debug_level == 'backtrace' && backtrace_log
      print args.join('').to_s
    elsif debug_level == 'stat' && stat_log
      print args.join('').to_s
    end
  end

  def no_gen_constructor_info
    { 'name_starts_with' =>
      %w[AstNode ClassElement TypedStatement Annotated Scope Type],
      'postfix_contains' =>
      ['= delete', 'override'],
      'arg_type' =>
      [{ 'name' => 'Tag' },
       { 'name' => 'Number', 'namespace' => 'lexer' },
       { 'name' => 'Property', 'namespace' => 'AstDumper' },
       { 'name' => 'TSChecker', 'namespace' => 'checker' },
       { 'name' => 'ArenaVector', 'template_args' => [{ 'type' => { 'name' => 'pair' } }] },
       { 'name' => 'initializer_list' }],
      'call_class' =>
      [{ 'name' => 'AstNode' }, { 'name' => 'ClassElement' }, { 'name' => 'TypedStatement' }, { 'name' => 'Annotated' },
       { 'name' => 'Scope' }, { 'name' => 'Type' }] }
  end

  def no_gen_method_info
    { 'name_starts_with' =>
      ['~', 'HasFloatingPoint', 'AddChildLambda', 'operator=', 'NumericConditionalCheck', 'CompileComputed'],
      'postfix_contains' =>
      ['= delete', 'override'],
      'return_type' =>
      [{ 'name' => 'ETSChecker' }, { 'name' => 'ArenaAllocator' },
       { 'name' => 'Allocator' }, { 'name' => 'Program' }, { 'name' => 'Tag' },
       { 'name' => 'Number', 'namespace' => 'lexer' }, { 'name' => 'Property', 'namespace' => 'AstDumper' },
       { 'name' => 'TSChecker', 'namespace' => 'checker' }],
      'arg_type' =>
      [{ 'name' => 'Tag' }, { 'name' => 'Number', 'namespace' => 'lexer' },
       { 'name' => 'Property', 'namespace' => 'AstDumper' }, { 'name' => 'TSChecker', 'namespace' => 'checker' },
       { 'name' => 'ArenaVector', 'template_args' => [{ 'type' => { 'name' => 'pair' } }] },
       { 'name' => 'initializer_list' }],
      'call_class' =>
      [{ 'name' => 'Annotated' }] }
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

  def stat_add_method(support)
    @all_methods += 1
    @supported_methods += support
  end

  def stat_add_constructor(support)
    @all_constructors += 1
    @supported_constructors += support
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
    Es2pandaLibApi.log('stat', "--------------\n")
    Es2pandaLibApi.log('stat', 'Supported methods: ', @supported_methods, ' / ', @all_methods, ' ( ',
                       @supported_methods / @all_methods * 100, " % )\n")
    Es2pandaLibApi.log('stat', 'Supported constructors: ', @supported_constructors, ' / ', @all_constructors, ' ( ',
                       @supported_constructors / @all_constructors * 100, " % )\n")
    Es2pandaLibApi.log('stat', "Classes with supported constructor: #{@classes_with_supported_constructor.size} / "\
        "#{@all_classes.size} ( #{@classes_with_supported_constructor.size.to_f / @all_classes.size * 100} % )\n")
    Es2pandaLibApi.log('stat', "--------------\n")

    return if @unsupported_types.empty?

    Es2pandaLibApi.log('stat', "Unsupported types for constructor: \n")
    sorted_items = @unsupported_types.sort_by { |_key, value| -value }
    sorted_items.each do |key, value|
      Es2pandaLibApi.log('stat', "#{key}: #{value}\n")
    end
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

  def ast_variables
    [%w[NO Variable],
     %w[LOCAL LocalVariable],
     %w[GLOBAL GlobalVariable],
     %w[MODULE ModuleVariable],
     %w[ENUM EnumVariable]]
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

    data['ir']&.class_definitions&.each do |class_definition|
      @classes[class_definition.name] = ClassData.new(class_definition&.public)
    end

    data.enums&.each do |enum|
      @enums << enum.name
    end

    Enums.wrap_data(data)
  end

  module_function :wrap_data, :classes, :ast_nodes, :includes, :change_types, :enums, :ast_types,
                  :stat_add_constructor, :stat_add_method, :print_stats, :no_gen_method_info, :no_gen_constructor_info,
                  :stat_add_class, :stat_add_unsupported_type, :ast_node_additional_children, :scopes, :ast_variables,
                  :code_gen_children, :check_fit, :log
end

def Gen.on_require(data)
  Es2pandaLibApi.wrap_data(data)
end
