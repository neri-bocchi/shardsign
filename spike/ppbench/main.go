// Command ppbench measures safe-prime / preparams generation cost.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"runtime"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

func main() {
	mode := flag.String("mode", "safeprime", "safeprime | preparams")
	n := flag.Int("n", 3, "repetitions")
	conc := flag.Int("c", 1, "concurrency")
	flag.Parse()
	runtime.GOMAXPROCS(*conc)
	for i := 0; i < *n; i++ {
		s := time.Now()
		switch *mode {
		case "safeprime":
			_, err := common.GetRandomSafePrimesConcurrent(context.Background(), 1024, 1, *conc, rand.Reader)
			if err != nil {
				panic(err)
			}
		case "preparams":
			if _, err := keygen.GeneratePreParams(30*time.Minute, *conc); err != nil {
				panic(err)
			}
		}
		fmt.Printf("%s #%d (GOOS=%s, c=%d): %s\n", *mode, i, runtime.GOOS, *conc, time.Since(s).Round(time.Millisecond))
	}
}
