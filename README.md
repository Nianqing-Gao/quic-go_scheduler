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
    -shortSize=1000 \
    -longSize=100000 \
    -logfile=./scts_local.csv
```
then run the client in another terminal:
```bash
go run ./example/datacenter_client \
    -ip 127.0.0.1:4242 \
    -nflows=20 \
    -shortFrac=0.9 \
    -shortSize=1000 \
    -longSize=100000 \
    -concurrency=3 \
    -scheduler=drr
```
log info should be printed on the terminal and also in the log file. 


go run ./example/datacenter_server -scheduler drr -shortSize 100000 -longSize 10000000 \
    -quantum0 7200 -quantum1 3600 -quantum2 1200


go run ./example/datacenter_client -scheduler drr -nflows 1000 -shortSize 100000 -longSize 10000000 \
    -quantum0 7200 -quantum1 3600 -quantum2 1200