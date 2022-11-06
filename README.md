# Crypto Server

```mermaid
graph LR;
  client1 --"1.plain text"--> server
  server --"2.encrypted || MAC"--> client1
  client2 ---> server
  subgraph clients
    direction TB
    client1
    client2
  end
  
  server <--> key_storage
```


## Build

Pull the submodules:

```sh
git submodule update --init --recursive
```

Create build directory.

```sh
mkdir build
cd build
```

Build the server.

```sh
cmake ..
make crypto_server
```

## Run

```sh
./crypto_server
```
