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
    keyLogFile := flag.String("keylog", "", "key log file (optional)")
    ip := flag.String("ip", "localhost:4242", "server IP:port")
    nflows := flag.Int("nflows", 100, "total number of flows (streams)")
    shortFrac := flag.Float64("shortFrac", 0.8, "fraction of short flows")
    shortSize := flag.Int("shortSize", 100*1024, "size of short flows in bytes")
    longSize := flag.Int("longSize", 10*1024*1024, "size of long flows in bytes")
    concurrency := flag.Int("concurrency", 10, "max concurrent streams")
    scheduler := flag.String("scheduler", "drr", "scheduler type: rr, wfq, abs, drr")
    flag.Parse()

    rand.Seed(time.Now().UnixNano())

    // QUIC config
    quicConfig := &quic.Config{
        DisablePathMTUDiscovery: true,
        TypePrio:                *scheduler,

        FlowSizeThresholds: []int{*shortSize, *longSize},
        FlowSizeQuantums:   []int{6 * 1200, 3 * 1200, 1 * 1200},
    }

    // TLS config
    tlsConf := &tls.Config{
        InsecureSkipVerify: true,
        NextProtos:         []string{"dctr-drr"},
    }

    if *keyLogFile != "" {
        f, err := os.Create(*keyLogFile)
        if err != nil {
            log.Fatalf("keylog create: %v", err)
        }
        defer f.Close()
        tlsConf.KeyLogWriter = f
    }

    // QUIC connection
    sess, err := quic.DialAddr(*ip, tlsConf, quicConfig)
    if err != nil {
        log.Fatalf("DialAddr error: %v", err)
    }
    defer sess.CloseWithError(0, "done")
    log.Printf("[client] connected to %s (scheduler=%s)", *ip, *scheduler)

    // Pre-generate flow sizes: 80% short, 20% long
    sizes := make([]int, *nflows)
    types := make([]string, *nflows)
    for i := 0; i < *nflows; i++ {
        if rand.Float64() < *shortFrac {
            sizes[i] = *shortSize
            types[i] = "short"
        } else {
            sizes[i] = *longSize
            types[i] = "long"
        }
    }

    // Limit concurrency
    sem := make(chan struct{}, *concurrency)
    var wg sync.WaitGroup

    for i := 0; i < *nflows; i++ {
        wg.Add(1)
        sem <- struct{}{}
        go func(id int, size int, class string) {
            defer wg.Done()
            defer func() { <-sem }()

            if err := runOneFlow(sess, id, size, class); err != nil {
                log.Printf("[client] flow %d (%s) error: %v", id, class, err)
            }
        }(i, sizes[i], types[i])
    }

    wg.Wait()
    log.Printf("[client] all flows completed")
}

func runOneFlow(sess quic.Connection, flowID int, size int, class string) error {
    stream, err := sess.OpenStreamSync(context.Background())
    if err != nil {
        return fmt.Errorf("OpenStreamSync: %w", err)
    }
    defer stream.Close()

    buf := make([]byte, 32*1024)
    remaining := size
    start := time.Now()

    for remaining > 0 {
        chunk := len(buf)
        if remaining < chunk {
            chunk = remaining
        }
        n, err := stream.Write(buf[:chunk])
        if err != nil {
            return fmt.Errorf("Write: %w", err)
        }
        remaining -= n
    }

    if err := stream.Close(); err != nil {
        return fmt.Errorf("Close: %w", err)
    }

    fct := time.Since(start)
    log.Printf("[client] flow %d (%s) complete: bytes=%d fct_ms=%.2f",
        flowID, class, size, float64(fct.Milliseconds()))
    return nil
}
