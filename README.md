Progress:
1. framer.go: main implementation of DRR scheduler
2. interface.go and config.go: added DRR-related fields
3. stream.go: added methods to allow applications to annotate flow size
4. example/datacenter_server/main.go: server implementation
5. example/datacenter_client/main.go: client implementation

Instruction:
To test locally (not in the ns-3 framework), first run the host:
```bash
go run ./example/datacenter_server \
    -ip 127.0.0.1:4242 \
    -scheduler=drr \
    -shortSize=100000 \
    -longSize=10000000 \
    -logfile=./scts_local.csv
```
then run the client in another terminal:
```bash
go run ./example/datacenter_client \
    -ip 127.0.0.1:4242 \
    -nflows=200 \
    -shortFrac=0.8 \
    -shortSize=100000 \
    -longSize=10000000 \
    -concurrency=10 \
    -scheduler=drr
```
log info should be printed on the terminal and also in the log file. 