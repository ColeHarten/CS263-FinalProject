# CS263-FinalProject

This uses llvm as a submodule. 

## Docker
To build the docker, in the `SensiTaint` directory run `make docker-run` to download the image which contains phasar and llvm.
Then, you can just hop in.

## Building
To build, go into the `SensiTaint/build/` directror and run:
```
mkdir -p build # make the build directory
cd build
cmake .. # generate build system using ../CMakeLists.txt
cmake --build .

```

Then to run the output, from `SensiTaint/`: 
```
./build/sensitaint ../test_dir/test.c test.
```