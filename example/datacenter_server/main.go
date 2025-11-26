package main

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "flag"
    // "fmt"
    quic "github.com/lucas-clemente/quic-go"
    "io"
    "log"
    "math/big"
    "net"
    "sync"
    "time"
)

func main() {
    ip := flag.String("ip", "0.0.0.0:4242", "IP:port to listen on")
    scheduler := flag.String("scheduler", "drr", "scheduler type: rr, wfq, abs, drr")
    flag.Parse()

    // Configure QUIC
    quicConfig := &quic.Config{
        AcceptToken: AcceptToken,
        TypePrio:    *scheduler,

        // Example flow-size-aware DRR config
        // thresholds in bytes: 100KB, 1MB
        FlowSizeThresholds: []int{100 * 1024, 1 * 1024 * 1024},
        // quantums: small flows get more credits per round
        FlowSizeQuantums:   []int{6 * 1200, 3 * 1200, 1 * 1200},
    }

    listener, err := quic.ListenAddr(*ip, generateTLSConfig(), quicConfig)
    if err != nil {
        log.Fatalf("ListenAddr error: %v", err)
    }
    log.Printf("[server] listening on %s (scheduler=%s)", *ip, *scheduler)

    for {
        conn, err := listener.Accept(context.Background())
        if err != nil {
            log.Printf("[server] Accept error: %v", err)
            continue
        }
        log.Printf("[server] new connection from %s", conn.RemoteAddr())
        go handleConnection(conn)
    }
}

func handleConnection(conn quic.Connection) {
    var wg sync.WaitGroup
    for {
        stream, err := conn.AcceptStream(context.Background())
        if err != nil {
            log.Printf("[server] AcceptStream error: %v", err)
            break
        }
        wg.Add(1)
        go func(s quic.Stream) {
            defer wg.Done()
            handleStream(s)
        }(stream)
    }
    wg.Wait()
    conn.CloseWithError(0, "done")
}

func handleStream(s quic.Stream) {
    id := s.StreamID()
    buf := make([]byte, 32*1024)
    var total int64
    start := time.Now()

    for {
        n, err := s.Read(buf)
        if n > 0 {
            total += int64(n)
        }
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Printf("[server] stream %d read error: %v", id, err)
            return
        }
    }

    fct := time.Since(start)
    log.Printf("[server] stream %d complete: bytes=%d fct_ms=%.2f",
        id, total, float64(fct.Milliseconds()))
}

func AcceptToken(clientAddr net.Addr, token *quic.Token) bool {
    // Simple: always accept tokens
    return true
}

func generateTLSConfig() *tls.Config {
    key, err := rsa.GenerateKey(rand.Reader, 1024)
    if err != nil {
        panic(err)
    }
    template := x509.Certificate{SerialNumber: big.NewInt(1)}
    certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
    if err != nil {
        panic(err)
    }
    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(key),
    })
    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: certDER,
    })

    tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        panic(err)
    }
    return &tls.Config{
        Certificates: []tls.Certificate{tlsCert},
        NextProtos:   []string{"dctr-drr"},
    }
}
