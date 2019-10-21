// Counter is a basic program that will increment a counter as fast as
// possilbe and report on the rate at which it was incremented. This is used
// for demonstrating the performance impact of different insturmetation.
package main

import (
	"flag"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var counter int64

//go:noinline
func doWork() {
	atomic.AddInt64(&counter, 1)
}

var report = flag.Bool("report", false, "Report the state of the counter every second.")

func main() {
	flag.Parse()

	fmt.Println("This is a blackbox. Read my counter.")

	if *report {
		go func() {
			p := message.NewPrinter(language.English)
			var prev int64
			for {
				count := atomic.LoadInt64(&counter)
				p.Printf("counter: %d\t(%d ops/s)\n", count, count-prev)
				prev = count
				time.Sleep(time.Second)
			}
		}()
	}
	for {
		doWork()
	}
}
