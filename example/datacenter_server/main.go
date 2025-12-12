package main

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "encoding/csv"
    "encoding/pem"
    "flag"
    "fmt"
    quic "github.com/lucas-clemente/quic-go"
    "log"
    "math/big"
    "net"
    "os"
    "strconv"
    "sync"
    "time"
    "io"
)

// global variables
var (
    csvWriter       *csv.Writer     // pointer to shared writer for all flows
    csvFile         *os.File        // pointer to shared log file for all flows 
    csvMu           sync.Mutex      // mutex to prevent concurrent writes
    schedulerName   string          // name of scheduler (drr, rr, wfq, drr)
    shortThresh     int             // threshold for short flow
    longThresh      int             // threshold for long flow
)

func main() {

    // flag name, default value, description
    ip := flag.String("ip", "0.0.0.0:4242", "IP:port to listen on")
    scheduler := flag.String("scheduler", "drr", "scheduler type: rr, wfq, abs, drr")
    logFile := flag.String("logfile", "/logs/scts.csv", "CSV log file path inside container")
    shortSize := flag.Int("shortSize", 100*1024, "short flow size threshold in bytes")
    longSize := flag.Int("longSize", 10*1024*1024, "long flow size threshold in bytes")
    quantum0 := flag.Int("quantum0", 6*1200, "quantum for class 0 (short flows)")
    quantum1 := flag.Int("quantum1", 3*1200, "quantum for class 1 (medium flows)")
    quantum2 := flag.Int("quantum2", 1*1200, "quantum for class 2 (long flows)")
    flag.Parse()

    schedulerName = *scheduler
    shortThresh = *shortSize
    longThresh = *longSize

    // log file
    f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("error when opening log file: %v", err)
    }
    csvFile = f
    csvWriter = csv.NewWriter(f)

    // write header if file is new
    fi, err := f.Stat()
    if err == nil && fi.Size() == 0 {
        csvMu.Lock()
        _ = csvWriter.Write([]string{"time_ms", "stream_id", "bytes", "sct_ms", "e2e_ms", "class", "scheduler"})
        csvWriter.Flush()
        csvMu.Unlock()
    }

    // quic configurations 
    quicConfig := &quic.Config{
        AcceptToken:          AcceptToken,
        TypePrio:             *scheduler,
        FlowSizeThresholds:   []int{*shortSize, *longSize},
        FlowSizeQuantums:     []int{*quantum0, *quantum1, *quantum2},
        MaxIdleTimeout:       3 * time.Minute, 
        MaxIncomingStreams:   100000,    // really just an arbitrary big number
    }

    // start a quic listener on ip:port 
    listener, err := quic.ListenAddr(*ip, generateTLSConfig(), quicConfig)
    if err != nil {
        log.Fatalf("ListenAddr error: %v", err)
    }
    log.Printf("[server] listening on %s (scheduler=%s)", *ip, *scheduler)

    // forever wait and accept incoming quic connections from clients
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

/* 
 * handle one connection
 */ 
func handleConnection(conn quic.Connection) {

    // track the number of goroutines that are processing streams on the given connection
    // we create a goroutine to handle each stream
    var wg sync.WaitGroup

    for {
        // blocks until a new stream is opened, the connection closes, or errors 
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

/*
 * classify assigns a length label based on the number of bytes in this stream
 */
func classify(bytes int64) string {
    if bytes <= int64(shortThresh) {
        return "short"
    }
    if bytes >= int64(longThresh) {
        return "long"
    }
    return "medium"
}

/*
 * assign length label based on bytes in the connection 
 */
func handleStream(s quic.Stream) {

    id := s.StreamID()                // unique identifier of stream within a connection 
    buffer := make([]byte, 32*1024)   // buffer holds up to 32 KB of data per read
    var total int64                   // total number of bytes received on this stream
    var start time.Time               // when first byte arrives at server
    var end time.Time                 // when last byte arrives at server
    var clientStartTime time.Time     // when client opened the stream
    var firstRead bool = true         // flag for first read to extract timestamp

    // read this stream until it's done
    for {
        n, err := s.Read(buffer)
        if n > 0 {
            // On first read, extract the client's start timestamp
            if firstRead {
                firstRead = false
                if n >= 8 {
                    // First 8 bytes contain the client start time in nanoseconds
                    tsNano := binary.BigEndian.Uint64(buffer[:8])
                    clientStartTime = time.Unix(0, int64(tsNano))
                    // Don't count the timestamp bytes in the total
                    total += int64(n - 8)
                } else {
                    log.Printf("[server] stream %d: insufficient bytes for timestamp", id)
                    total += int64(n)
                }
            } else {
                total += int64(n)
            }
            
            if start.IsZero() {
                start = time.Now()
            }
        }
        if err != nil {
            if err == io.EOF {
                if start.IsZero() {
                    start = time.Now()
                }
                end = time.Now()
                break
            }
            log.Printf("[server] stream %d read error: %v", id, err)
            return
        }
    }

    sctMs := end.Sub(start).Seconds() * 1000.0           // server completion time
    endToEndMs := end.Sub(clientStartTime).Seconds() * 1000.0  // end-to-end time
    class := classify(total)          // classify this stream  

    log.Printf("[server] stream %d complete: bytes=%d sct_ms=%.2f e2e_ms=%.2f class=%s",
        id, total, sctMs, endToEndMs, class)

    // log to csv 
    csvMu.Lock()
    defer csvMu.Unlock()

    // prepare one row 
    row := []string{
        strconv.FormatInt(time.Now().UnixMilli(), 10),      // current time in ms
        strconv.FormatInt(int64(id), 10),                   // stream id
        strconv.FormatInt(total, 10),                       // stream length (excluding timestamp)
        fmt.Sprintf("%.2f", sctMs),                         // stream completion time in ms
        fmt.Sprintf("%.2f", endToEndMs),                    // end-to-end time in ms
        class,                                              // class (length)
        schedulerName,                                      // scheduler name
    }
    // write to csv
    if err := csvWriter.Write(row); err != nil {
        log.Printf("[server] CSV write error: %v", err)
    }
    csvWriter.Flush()
}

/* 
 * accept every token 
 * token is for client address validation. since we do not care about 
 * security for the purpose of this experiment, we trust that every 
 * client has a valid address
 */
func AcceptToken(clientAddr net.Addr, token *quic.Token) bool {
    return true
}

/*
 * create TLS certificate and a private key for the server
 * TLS (transport layer security) is a protocol that encrypt data 
 * between client and server. it uses a handshake to authenticate
 * the server 
 */
func generateTLSConfig() *tls.Config {

    // generate a random private key
    key, err := rsa.GenerateKey(rand.Reader, 1024)
    if err != nil {
        log.Fatalf("[server] failed to generate RSA key: %v", err)
    }
    // create certificate and sign it with this key
    template := x509.Certificate{SerialNumber: big.NewInt(1)}
    certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
    if err != nil {
        log.Fatalf("[server] failed to create certificate: %v", err)
    }
    // create PEM files to store the key and certificate
    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(key),
    })
    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: certDER,
    })
    // make pairs
    tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        panic(err)
    }
    return &tls.Config{
        Certificates: []tls.Certificate{tlsCert},
        NextProtos:   []string{"dctr-drr"},        // client & server shared protocol
    }
}
