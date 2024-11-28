# crypto-algs-comparison
Benchmarking of AES, RSA and ECC.

# Building
After cloning this repo, navigate to the directory you cloned into.
```
cmake -S . -B /bin
cd bin
make
```

# Usage
Run the excecutable generated previously. First input is the file to run benchmarks based on. Second is the key size. Recommended key sizes are **1024, 2048, 4096**. It will generate a ```benchmarks.txt``` file with the results.
