# Es2panda

All in one JavaScript/TypeScript parser and compiler.

## Usage
```sh
es2panda [OPTIONS] [input file] -- [arguments]
```

## Optional arguments
[util/options.yaml](util/options.yaml)

## Tail arguments
 - `input`: input file

## Running the tests
```sh
pip install tqdm
```
```sh
python3 test/runner.py [OPTIONS] [build_directory]
```

### Optional arguments
 - `--regression`: Run regression tests
 - `--test262`: Run test262
 - `--no-progress`: Don't show progress bar

### Tail arguments
 - `build_directory`: Path to panda build directory

### Skip list
Skip list for the runtime: `test/test262skiplist.txt, test/test262skiplist-long.txt`.
