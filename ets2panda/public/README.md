# es2panda_lib generation

> What is it?

Automatic export of ArkTS public classes and methods into C API.

> I fixed CODECHECK and got a new failure "UNSUPPORTED TYPE".

1) Check if your new method should be private and automatically excluded from C API, error will disappear.

2) Otherwise support method arguments types in `cppToCTypes.yaml`.

> What is `cppToCTypes.yaml`

It describes how C++ types should be transformed into C types in plugin API.
Tranformation "one to many" is supported to express map of e.g. `std::vector<int>` to `int*, size_t pair` pair.

## How to add new type:

1) Copy the template below to the end of [cppToCTypes.yaml](./cppToCTypes.yaml).

    <details><summary>Template</summary>

    ```yaml
      # Describes C++ original argument.
      - es2panda_arg:
          name: '|arg_name|'
          type:
            name: 'FunctionSignature'
            namespace: 'ir' # optional
          min_ptr_depth: 1  # optional
          max_ptr_depth: 1  # optional

      # Describes C arguments, into which the original argument will be expanded.
        new_args:
        - type:
            name: "es2panda_FunctionSignature"
            ptr_depth: '|es2panda_arg.type.ptr_depth_int|'
          name: '|arg_name|'
          namespace: "ir::"

      # Describes additional C return arguments IF original argument is return type and expands to multiple arguments.
        return_args:
        - type:
            name: size_t
            ptr_depth: 1
          name: '|arg_name|Len'

        cast:
          # Create C++ variable from C argument.
            expression: >-
              auto |es2panda_arg.type.ptr_depth||arg_name|E2p =
              reinterpret_cast<ir::FunctionSignature |es2panda_arg.type.ptr_depth|>(|arg_name|);

          # Create C variable from C++ return value.
            reverse_cast:
              start: >-
                reinterpret_cast<?const? es2panda_FunctionSignature |es2panda_arg.type.ptr_depth|>

          # Cast C argument to C++ class, to call method from it.
            call_cast:
              call_var: 'es2panda_FunctionSignature *ast'
              start: >-
                (reinterpret_cast<?const? ir::FunctionSignature *>(ast))->

          # Create new class and return C++ pointer to it.
            constructor_cast:
              start: >-
                ctxAllocator->New<ir::FunctionSignature>(
              end: )

          # Name of veriable, created by expression.
            var_name: '|arg_name|E2p'
    ```

    </details>

2) Remove comments.
3) Remove unnecessary fields:
    - `return_args` is needed only if you return new type from function and this type expands to multiple arguments.
    - `reverse_cast` is needed only if you return new type from function.
    - `call_cast` is needed only if you add new class to generation.
    - `constructor_cast` is needed only if you add new class to generation.
4) Modify it for new type. Below you can see [Template description](#template-description).

## Template description:
All non-basic types are described in [cppToCTypes.yaml](./cppToCTypes.yaml).  

There are 4 keys in first layer:
1) `es2panda_arg`: describes original C++ argument. It is used to match which **template** from `cppToCTypes.yaml` should be used for current argument.  

    <details><summary>More info</summary>

    FunctionSignature in `cppToCTypes.yaml`:
    ```yaml
    es2panda_arg:
        name: '|arg_name|'
        type:
            name: 'FunctionSignature'
            namespace: 'ir'
        min_ptr_depth: 1
    ```

    ### Generator finds match if:
    ```
    original_argument['type']['name']      == es2panda_arg['type']['name'] &&
    original_argument['type']['namespace'] == es2panda_arg['type']['namespace'] &&
    original_argument['type']['ptr_depth'] >= es2panda_arg['min_ptr_depth'] &&
    original_argument['type']['ptr_depth'] <= es2panda_arg['max_ptr_depth']
    ```
    If any of the fields are missing, the generator will skip the corresponding check (except for the type::name field).  

    ### What is `|arg_name|`:
    It is placeholder. After matching **template**, generator stores placeholder values:
    ```ruby
    # Generator finds placeholder |arg_name| in es2panda_arg['name']
    # It stores the same value from original_argument:
    |arg_name| = original_argument['type']
    ```

    You can utilize this placeholder in various contexts, and it will be substituted with the saved value.

    ### Addressing other fields not outlined in the **template**:
    Following the alignment of the **template** and retention of placeholder values, es2panda_arg is supplanted by original_argument. Hence, other attributes are preserved.

    ### Clarification on ptr_depth and ref_depth:

    `ptr_depth` is number of `*` in argument.  
    `ref_depth` is number of `&` in argument.  

    #### Why is it needed:
    `min_ptr_depth` and `max_ptr_depth` are needed to separate 0 and 1+ ptr-cases, because the es2panda API stores pointers to empty structures and is not able to provide an instance of the class, only a pointer to it (except for primitive C types).  
    For example:  
        `AstNode` -> `es2panda_AstNode *`  
        `AstNode *` -> `es2panda_AstNode *`  
        `AstNode **` -> `es2panda_AstNode **`  
    Where es2panda_AstNode is pointer to empty structure in es2panda API.

    ---
    </details>

2) `new_args`: describes C arguments, into which the original argument will be expanded.

    <details><summary>More info</summary>

    FunctionSignature in `cppToCTypes.yaml`:
    ```yaml
    new_args:
        - type:
            name: "es2panda_FunctionSignature"
            ptr_depth: 1
        name: '|arg_name|'
        namespace: "ir::"
    ```

    Describes argument for C-API:
    ```c++
    // original C++ argument:
    ir::FunctionSignature *MyVarName

    // new C argument:
    es2panda_FunctionSignature *MyVarName
    ```

    **Note:** please manually write namespace in the format like `ir::` (with `::`).

    ---
    </details>

3) `return_args`: describes additional C return arguments IF original argument is return type and expands to multiple arguments.

    <details><summary>More info</summary>

    FunctionSignature in `cppToCTypes.yaml`:
    ```yaml
    - name: '|arg_name|Len'
      type:
        name: size_t
        ptr_depth: 1
    ```

    ### When it is needed:
    If `original_argument` expands to **several argument** and if it is **return type** additional arguments should appear, through which the necessary values will be returned.  
    For example:
    ```c++
    // Example: ArenaVector<int> -> int *, size_t *

    // C++ function
    ArenaVector<int> Foo();

    // C-API function
    int *FooInAPI(size_t *arenaVectorLen /* return argument appeared */)
    ```

    ---
    </details>

4) `cast`:
    - `expression`: create C++ variable from C argument.

        <details><summary>More info</summary>

        FunctionSignature in `cppToCTypes.yaml`:
        ```yaml
        expression: >-
            auto |es2panda_arg.type.ptr_depth||arg_name|E2p =
            reinterpret_cast<ir::FunctionSignature |es2panda_arg.type.ptr_depth|>(|arg_name|);
        ```

        Result:
        ```c++
        // C++ function
        void Foo(FunctionSignature *myArgument);

        // C-API function
        void FooInAPI(es2panda_FunctionSignature *myArgument) {
            auto *myArgumentE2p = reinterpret_cast<ir::FunctionSignature *>(myArgument);
            // ... other code
        }
        ```

        ### Note:
        You can see clever placeholder `|es2panda_arg.type.ptr_depth|`. It allows to get value from `es2panda_arg['type']['ptr_depth']`.  
        If `es2panda_arg['type']['ptr_depth'] = 2`, then `|es2panda_arg.type.ptr_depth|` will be raplaced with `**` and `|es2panda_arg.type.ptr_depth_int|` will be replaced with `2`.

        ---
        </details>

    - `reverse_cast`: create C variable from C++ return value.

        <details><summary>More info</summary>

        FunctionSignature in `cppToCTypes.yaml`:
        ```yaml
        reverse_cast:
            start: >-
                reinterpret_cast<?const? es2panda_FunctionSignature |es2panda_arg.type.ptr_depth|>
        ```

        Result:
        ```c++
        // C++ function
        FunctionSignature *Foo();

        // C-API function
        es2panda_FunctionSignature *FooInAPI() {
            // auto res = reverse_cast['start']( Foo() )reverse_cast['end']
            auto res = reinterpret_cast<es2panda_FunctionSignature *>(Foo());
            return res;
        }
        ```

        ### Note:
        You can see `?const?`, it will be replaced with `const` if the type is const, and will be deleted otherwise.

        ---
        </details>

    - `call_cast`: cast C argument to C++ class, to call method from it.

        <details><summary>More info</summary>

        FunctionSignature in `cppToCTypes.yaml`:
        ```yaml
        call_cast:
            call_var: 'es2panda_FunctionSignature *ast'
            start: >-
                (reinterpret_cast<?const? ir::FunctionSignature *>(ast))->
        ```

        Result:
        ```c++
        // C++ method
        class FunctionSignature {
            void Foo();
        }

        // C-API function
        void FooInAPI(es2panda_FunctionSignature *ast /* call_var appeared */) {
            // call_cast['start']Foo();
            (reinterpret_cast<ir::FunctionSignature *>(ast))->Foo();
        }

        ```

        `call_var`: additional C argument - class pointer, to call method from.

        ### Note:
        You can see `?const?`, it will be replaced with `const` if the type is const, and will be deleted otherwise.

        ---
        </details>


    - `constructor_cast`: create new class and return C++ pointer to it.

        <details><summary>More info</summary>

        FunctionSignature in `cppToCTypes.yaml`:
        ```yaml
        constructor_cast:
            start: >-
                ctxAllocator->New<ir::FunctionSignature>(
            end: )
        ```

        Result:
        ```c++
        // C++ constructor
        class FunctionSignature {
            FunctionSignature(int arg1, int arg2);
        }

        // C-API function
        es2panda_FunctionSignature FunctionSignatureInAPI(int arg1, int arg2) {
            // return reverse_cast['start']( constructor_cast['start'] <ARGUMENTS> constructor_cast['end'] )reverse_cast['end']
            return reinterpret_cast<es2panda_FunctionSignature *>(/* constructor cast -> */ ctxAllocator->New<ir::FunctionSignature>(arg1, arg2));
        }
        ```

        ### Note:
        Using only in constructors. Constructor cast is wrapped by reverse cast.

        ---
        </details>

    - `var_name`: name of veriable, created by expression.

        <details><summary>More info</summary>

        FunctionSignature in `cppToCTypes.yaml`:
        ```yaml
        var_name: '|arg_name|E2p'
        ```

        Result:
        ```c++
        // C++ function
        void Foo(FunctionSignature *myArgument);

        // C-API function
        void FooInAPI(es2panda_FunctionSignature *myArgument) {
            // expression:
            auto *myArgumentE2p = reinterpret_cast<ir::FunctionSignature *>(myArgument);

            // ... other code

            // calling C++ function, using new variable with name 'var_name'
            Foo(myArgumentE2p /* var_name */);
        }
        ```

        ---
        </details>


es2panda_lib_decl.inc, es2panda_lib_enums.inc, es2panda_lib_impl.inc, es2panda_lib_include.inc, es2panda_lib_list.inc

## How to run:
```bash
ninja gen_api   # only generates *.inc files.

ninja es2panda-public   # compiles es2panda_lib
```

You can find generated files in `<build>/tools/es2panda/generated/es2panda_lib`.

## Tests:
Tests are located in `ets_frontend/ets2panda/test/unit/public`, their names start with "e2p_test_plugin".

Run tests:
```bash
ninja es2panda-plugin-test
```
