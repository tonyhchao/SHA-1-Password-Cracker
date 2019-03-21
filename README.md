## Prerequisites
Install OpenSSL library:
- Debian-based Linux distributives:
```bash
sudo apt-get install libssl-dev
```

- OS X:
```bash
brew install openssl
```

## USAGE
In order to run the program fast on multiprocessor system, you should run in bash:
```bash
cmake -DCMAKE_BUILD_TYPE=Release
make
NPROCS=4
time seq 0 $((NPROCS-1)) | xargs -P $NPROCS -I{} -n 1 ./password_cracker {} $NPROCS
```

Make sure you have gcc c++ install in your environment along side with OpenSSL Library.
If you don't have gcc c++ install, use the following command in Ubuntu:
```
sudo apt-get install gcc c++
```

You can set the variable NPROCS to whatever number of processors you have. On Ubuntu it may be easilty evaluated with command:
```bash
nproc
```

