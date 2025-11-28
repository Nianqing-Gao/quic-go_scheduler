package main

import (
    "context"
    "crypto/tls"
    "flag"
    "fmt"
    quic "github.com/lucas-clemente/quic-go"
    "log"
    "math/rand"
    "sync"
    "time"
	"os"
)

func main() {

    // flag name, default value, description
    duration := flag.Duration("duration", 0, "optional total run time (e.g. 5m, 300s); 0 = run until all flows finish")
    keyLogFile := flag.String("keylog", "", "key log file (optional)")
    ip := flag.String("ip", "localhost:4242", "server IP:port")
    nflows := flag.Int("nflows", 100, "total number of flows (streams)")
    shortFrac := flag.Float64("shortFrac", 0.8, "fraction of short flows")
    shortSize := flag.Int("shortSize", 100*1024, "size of short flows in bytes")
    longSize := flag.Int("longSize", 10*1024*1024, "size of long flows in bytes")
    concurrency := flag.Int("concurrency", 10, "max concurrent streams")
    scheduler := flag.String("scheduler", "drr", "scheduler type: rr, wfq, abs, drr")
    flag.Parse()

    rand.Seed(time.Now().UnixNano())           // for randomizing flow class

    // quic configurations
    quicConfig := &quic.Config{

        DisablePathMTUDiscovery: true,                      // disable MTU discovery
        TypePrio:                *scheduler,                // 
        FlowSizeThresholds: []int{*shortSize, *longSize},   // length class thresholds
        FlowSizeQuantums:   []int{6*1200, 3*1200, 1*1200},  // quantum each class gets per round
    }
    // TLS configurations
    tlsConf := &tls.Config{
        InsecureSkipVerify: true,                           // client does not verify server cert
        NextProtos:         []string{"dctr-drr"},           // client & server shared protocol
    }
    // key log file 
    if *keyLogFile != "" {
        f, err := os.Create(*keyLogFile)
        if err != nil {
            log.Fatalf("keylog create: %v", err)
        }
        defer f.Close()
        tlsConf.KeyLogWriter = f
    }

    // establish quic connection session to server at *ip using tlsConf and quicConf
    sess, err := quic.DialAddr(*ip, tlsConf, quicConfig)
    if err != nil {
        log.Fatalf("DialAddr error: %v", err)
    }
    // close session when done
    defer sess.CloseWithError(0, "done")
    log.Printf("[client] connected to %s (scheduler=%s)", *ip, *scheduler)

    // generate randomized flow size and class accordingly (80% short, 20% long)
    sizes := make([]int, *nflows)
    class := make([]string, *nflows)
    for i := 0; i < *nflows; i++ {
        if rand.Float64() < *shortFrac {
            sizes[i] = *shortSize
            class[i] = "short"
        } else {
            sizes[i] = *longSize
            class[i] = "long"
        }
    }

    // limit concurrency with semaphore
    // only concurrency number of goroutines can use the channel
    sem := make(chan struct{}, *concurrency)
    var wg sync.WaitGroup

    startAll := time.Now()

    // start a goroutine for each flow 
    for i := 0; i < *nflows; i++ {
        // duration check
        if *duration > 0 && time.Since(startAll) > *duration {
            log.Printf("[client] duration limit hit - not starting flow %d and beyond", i)
            break
        }

        wg.Add(1)
        sem <- struct{}{}
        go func(id int, size int, class string) {
            defer wg.Done()           // mark goroutine as done
            defer func() { <-sem }()  // release semaphore
            if err := runOneFlow(sess, id, size, class); err != nil {
                log.Printf("[client] flow %d (%s) error: %v", id, class, err)
            }
        }(i, sizes[i], class[i])
    }
    // wait for all flows to complete
    wg.Wait()
    log.Printf("[client] all streams completed")
}

/*
 * open a single quic stream on the existing connection,
 * log the flow completion time
 * - size: number of bytes to send
 * - class: short, medium, long
 */
func runOneFlow(sess quic.Connection, flowID int, size int, class string) error {
    // open one stream 
    stream, err := sess.OpenStreamSync(context.Background())
    if err != nil {
        return fmt.Errorf("OpenStreamSync: %w", err)
    }
    // close stream when done
    defer stream.Close()
    // allocate write buffer
    buf := make([]byte, 32*1024)
    remaining := size

    start := time.Now()
    for remaining > 0 {
        // decide how many bytes to send in this iteration
        // either send full buffer or whatever's left
        send := len(buf)
        if remaining < send {
            send = remaining
        }
        // write "send" bytes to stream 
        n, err := stream.Write(buf[:send])
        if err != nil {
            return fmt.Errorf("Write: %w", err)
        }
        remaining -= n
    }

    sct := time.Since(start)
    log.Printf("[client] stream %d (%s) complete: bytes=%d sct_ms=%.2f",
        flowID, class, size, float64(sct.Milliseconds()))
        
    return nil
}
