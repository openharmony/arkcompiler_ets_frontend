# Es2panda Dependency analyzer

Defining dependencies between files. Not including standard library files. 


> What is it?

Import dependency analyzer between files.

> Added special case handling.

1) Standard libraries are not handled by our dependency analyzer.

2) To prevent loops, it is checked whether this file has been processed before. If so, we skip it.

> The result

The result of the program is std::vector of full file paths. The paths in the array are sorted by import precedence.

If any imported file was not found, the program returns with an error, otherwise it returns 0.

## Usage

```
dependency_analyzer [input_file] [OPTIONS]
```

## Arguments

- `input`: input file

### Optional arguments
- `--output`: dump output file. 
Type of dump to a output file:

```
<Input file absolute path>
<First include-file absolute path>
<Second include-file absolute path>
...
```

## Running the tests

```
es2panda_depanalyz_tests
```