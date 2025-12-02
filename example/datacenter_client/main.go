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
    "math"
)

func main() {

    // flag name, default value, description
    duration := flag.Duration("duration", 0, "optional total run time (e.g. 5m, 300s); 0 = run until all flows finish")
    keyLogFile := flag.String("keylog", "", "key log file (optional)")
    ip := flag.String("ip", "localhost:4242", "server IP:port")
    nflows := flag.Int("nflows", 1000, "total number of flows (streams)")
    minSize := flag.Int("minSize", 2*1024, "minimum flow size in bytes (default: 2KB)")
    maxSize := flag.Int("maxSize", 11*1024*1024, "maximum flow size in bytes (default: 1.1MB)")
    shortFrac := flag.Float64("shortFrac", 0.9, "fraction of short flows")
    shortSize := flag.Int("shortSize", 100*1024, "size of short flows in bytes (anything below 1MB)")
    longSize := flag.Int("longSize", 10*1024*1024, "size of long flows in bytes (anything beyond 1MB)")
    concurrency := flag.Int("concurrency", 10, "max concurrent streams")
    scheduler := flag.String("scheduler", "drr", "scheduler type: rr, wfq, abs, drr")
    quantum0 := flag.Int("quantum0", 6*1200, "quantum for class 0 (short flows)")
    quantum1 := flag.Int("quantum1", 3*1200, "quantum for class 1 (medium flows)")
    quantum2 := flag.Int("quantum2", 1*1200, "quantum for class 2 (long flows)")
    flag.Parse()

    rand.Seed(time.Now().UnixNano())           // for randomizing flow class

    // generate randomized flow size and class
    sizes := make([]int, *nflows)
    classes := make([]string, *nflows)
    shortCount, medCount, longCount := 0, 0, 0

    for i := 0; i < *nflows; i++ {
        u := rand.Float64()
        var size int
        if u < *shortFrac {
            // short flows: draw between [minSize, shortSize)
            size = sampleLogUniform(*minSize, max(1, *shortSize-1))
        } else {
            // the rest: draw between [shortSize, maxSize]
            size = sampleLogUniform(*shortSize, *maxSize)
        }
        sizes[i] = size
        // classify based on thresholds
        if size < *shortSize {
            classes[i] = "short"
            shortCount++
        } else if size < *longSize {
            classes[i] = "medium"
            medCount++
        } else {
            classes[i] = "long"
            longCount++
        }
    }
    _ = shortCount
    _ = medCount
    _ = longCount

    // quic configurations
    quicConfig := &quic.Config{

        DisablePathMTUDiscovery: true,                      // disable MTU discovery
        TypePrio:                *scheduler,                // 
        FlowSizeThresholds: []int{*shortSize, *longSize},   // length class thresholds
        FlowSizeQuantums:   []int{*quantum0, *quantum1, *quantum2},  // quantum each class gets per round
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

    if *scheduler == "wfq" || *scheduler == "abs" {
        streamPrio := make([]int, *nflows)
        for i := 0; i < *nflows; i++ {
            switch classes[i] {
            case "short":
                streamPrio[i] = 3  // highest
            case "medium":
                streamPrio[i] = 2
            case "long":
                streamPrio[i] = 1  // lowest
            }
        }
        quicConfig.StreamPrio = streamPrio
    }

    // establish quic connection session to server at *ip using tlsConf and quicConf
    sess, err := quic.DialAddr(*ip, tlsConf, quicConfig)
    if err != nil {
        log.Fatalf("DialAddr error: %v", err)
    }
    // close session when done
    defer sess.CloseWithError(0, "done")
    log.Printf("[client] connected to %s (scheduler=%s)", *ip, *scheduler)

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
        }(i, sizes[i], classes[i])
    }
    // wait for all flows to complete
    wg.Wait()
    log.Printf("[client] all streams completed")
}

/*
 * helper function for generating synthetic data
 */
func sampleLogUniform(minSize, maxSize int) int {
    if minSize <= 0 {
        minSize = 1
    }
    if maxSize <= minSize {
        return minSize
    }
    logMin := math.Log(float64(minSize))
    logMax := math.Log(float64(maxSize))
    u := rand.Float64()
    v := logMin + u*(logMax-logMin)
    return int(math.Exp(v))
}
/*
 * helper function for generating synthetic data
 */
func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

/*
 * open a single quic stream on the existing connection,
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

    // start := time.Now()
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

    // sct := time.Since(start)
    // log.Printf("[client] stream %d (%s) complete: bytes=%d sct_ms=%.2f",
    //     flowID, class, size, float64(sct.Milliseconds()))
        
    return nil
}
