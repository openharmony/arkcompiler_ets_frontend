# es2panda_lib generation

### How to run:
```bash
ninja gen_api   # only generates es2panda_lib.cpp and es2panda_lib.h

ninja es2panda-public   # compiles es2panda_lib
```

### Tests:
Tests are located in `ets_frontend/ets2panda/test/unit/public`, their names start with "e2p_test_plugin".

Run tests:
```bash
ninja es2panda-plugin-test
```


## Notes, how to work with cppToCTypes.yaml
In the c++ code of es2panda, there are types that are not presents in c. es2panda_lib must have a c interface. cppToCTypes.yaml describes the translation of complex types from c++ to c.

Why do we describe working with arguments and not with types? Because 1 argument from c++ can expand into several c arguments. For example, `std::vector<int> A` in c will be represented as `int* A, int ALen`.


Let's look at the example of `std::pair<type_1, type_2> some_name` how to use this yaml:


### es2panda_arg
This is the key field that is used for pattern matching! Patterns in the form of `|some_identifier|`.

```
- es2panda_arg:
    name: '|arg_name|'
    type:
        name: std::pair
        template_args:
        - type: '|first_type|'
        - type: '|seond_type|'
```

Let's assume that in .rb, the search for arguments suitable for this template takes place using validation:
`es2panda_arg["type"]["name"] == candidate_arg["type"]["name"]`.

Suppose our candidate is `std::pair<int*, int> A`.
Parsed to yaml is:
```
- name: A
  type:
    name: std::pair
    template_args:
    - type:
        name: int
        ptr_depth: 1
    - type:
        name: int
```

es2panda_arg ONLY serves to match templates for the desired type from c++.

In our example we'll have:
```
|arg_name| = A
|first_type| = {"name": int, "ptr_depth": 1}
|second_type| = {"name": int}
```

In any subsequent fields in cppToCTypes.yaml we can use these templates. They will be replaced with the desired values.

IMPORTANT! The raw argument from es2panda will be saved intact and will not be changed. Therefore, it is not necessary to describe all possible fields for an argument in es2panda_arg, only those that are used to match templates of the form `|some_field|` and filter the argument that fits this template (usually `es2panda["type"]["name"]`) are needed.

### Features
Not in es2panda args you can use `|some_code|` pattern like .rb code snippet. 

Example:
```rb
|es2panda_arg.type.ptr_depth|
# or
|new_args.0.type.ptr_depth|
```

Note: Recall that es2panda_arg is used only for pattern matching, and after matching, the raw es2panda argument is copied in its entirety. Therefore, even if you did not describe the ptr_depth field in es2panda_arg, but it is in the raw argument itself, you will be able to get this value.
