package main

import (
    "context"
    "crypto/tls"
    "encoding/binary"
    "flag"
    "fmt"
    quic "github.com/lucas-clemente/quic-go"
    "log"
    "math/rand"
    "sync"
    "time"
    "math"
)

func main() {

    rand.Seed(time.Now().UnixNano())

    // flag name, default value, description
    duration := flag.Duration("duration", 0, "optional total run time (e.g. 5m, 300s); 0 = run until all flows finish")
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
    dataType := flag.String("dataType", "threePoints", "how synthetic data length is drawn ('threePoints' or 'logUniform')")
    flag.Parse()

    // bookeeping for synthetic workflows
    sizes := make([]int, *nflows)
    classes := make([]string, *nflows)

    switch *dataType {
    case "threePoints":
        sizes, classes = sampleThreePoints(*shortSize, *longSize, *nflows, *shortFrac, sizes, classes)
    case "logUniform":
        sizes, classes = sampleLogUniform(*minSize, *maxSize, *shortSize, *longSize, *nflows, *shortFrac, sizes, classes)
    default:
        panic("Invalid data type")
    }

    // QUIC configurations
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

    if *scheduler == "wfq" || *scheduler == "abs" {
        streamPrio := make([]int, *nflows)
        for i := 0; i < *nflows; i++ {
            switch classes[i] {
            case "short":
                streamPrio[i] = 3  // highest
            case "medium":
                streamPrio[i] = 2  // medium
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
    defer sess.CloseWithError(0, "done")
    log.Printf("[client] connected to %s (scheduler=%s)", *ip, *scheduler)

    // limit concurrency with semaphore
    // the number of concurrency is the maximum number of streams allowed in single connection
    sem := make(chan struct{}, *concurrency)
    var wg sync.WaitGroup

    startAll := time.Now()

    // one goroutine for each flow 
    for i := 0; i < *nflows; i++ {
        // duration check
        if *duration > 0 && time.Since(startAll) > *duration {
            log.Printf("[client] duration limit hit - not starting flow %d and beyond", i)
            break
        }
        wg.Add(1)
        sem <- struct{}{}
        go func(id int, size int, class string) {
            defer wg.Done()           
            defer func() { <-sem }()
            if err := runOneStream(sess, id, size, class); err != nil {
                log.Printf("[client] flow %d (%s) error: %v", id, class, err)
            }
        }(i, sizes[i], classes[i])
    }
    wg.Wait()
    log.Printf("[client] all streams completed")
}

func sampleThreePoints(shortSize int, longSize int, nflows int, shortFrac float64, sizes []int, classes []string) ([]int, []string) {
    shortFlowSize  := shortSize / 2
    mediumFlowSize := (shortSize + longSize) / 2
    longFlowSize   := longSize + (longSize-shortSize)/2

    // sample flow sizes from three fixed points
    for i := 0; i < nflows; i++ {
        u := rand.Float64()
        var size int

        if u < shortFrac {
            size = shortFlowSize
        } else {
            v := rand.Float64()
            if v < 0.5 {
                size = mediumFlowSize
            } else {
                size = longFlowSize
            }
        }

        sizes[i] = size
        if size < shortSize {
            classes[i] = "short"
        } else if size < longSize {
            classes[i] = "medium"
        } else {
            classes[i] = "long"
        }
    }
    return sizes, classes
}

func sampleLogUniform(minSize int, maxSize int, shortSize int, longSize int, nflows int, shortFrac float64, sizes []int, classes []string) ([]int, []string) {

    for i := 0; i < nflows; i++ {
        u := rand.Float64()
        var size int
        if u < shortFrac {
            // short flows are draw between [minSize, shortSize)
            size = sampleHelper(minSize, max(1, shortSize-1))
        } else {
            // the rest are draw between [shortSize, maxSize]
            size = sampleHelper(shortSize, maxSize)
        }

        sizes[i] = size
        if size < shortSize {
            classes[i] = "short"
        } else if size < longSize {
            classes[i] = "medium"
        } else {
            classes[i] = "long"
        }
    }
    return sizes, classes
}

func sampleHelper(minSize int, maxSize int) int {
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
func runOneStream(sess quic.Connection, flowID int, size int, class string) error {

    stream, err := sess.OpenStreamSync(context.Background())
    if err != nil {
        return fmt.Errorf("OpenStreamSync: %w", err)
    }

    // Set the flow size (including the 8 bytes for timestamp)
    if drrConn, ok := sess.(interface {
        SetStreamFlowSize(quic.StreamID, uint64)
    }); ok {
        drrConn.SetStreamFlowSize(stream.StreamID(), uint64(size+8))
        // fmt.Printf("[CLIENT] Flow %d: SetStreamFlowSize SUCCESS\n", flowID)
    }

    // Send client start timestamp as first 8 bytes
    startNano := time.Now().UnixNano()
    tsBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(tsBytes, uint64(startNano))
    
    if _, err := stream.Write(tsBytes); err != nil {
        return fmt.Errorf("Write timestamp: %w", err)
    }

    defer stream.Close()

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
