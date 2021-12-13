# ArgleBargleGarble
This is an implementation of [Two halves make a whole](https://doi.org/10.1007/978-3-662-46803-6_8) and [Fast garbling of circuits under standard assumptions](https://doi.org/10.1007/s00145-017-9271-y) (with the exception of the Related-Key scheme in the second) in Python 3.10. It also includes a simple C extension for AES implemented with AES-NI instructions.

It is not meant to be a fully optimised implementation, nor is it meant to be production ready.

If you want to run the code, you should first run
```shell
$ cd pyaesni
$ ./setup.py install
$ cd ..
```
to install the C extension used for AES encryption. (This requires a C++ compiler.) The code so that it'll work without the C extension installed, but you'll have to change the definition of `gen_hash` to use `aes_hash` (which depends on [pycryptodomex](https://pypi.org/project/pycryptodomex/) and is significantly slower) or `sha_hash`.

You can then run
```shell
$ ./curl-circuits.sh
```
to download some test circuits from https://homes.esat.kuleuven.be/~nsmart/MPC/. You can then run
```shell
$ ./run-tests.sh > results.csv
```
to run test the code and output a summary as a CSV file. You can add or remove circuits in the `circuits.sh` file. You can supply a `-n <iterations>` argument to repeat the tests several times for more accurate results.
