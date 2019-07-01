// LowHZ uses delve to measure the global counter variable of the counter
// process once every second and reports on the rate it is being incremented
// at. This is an examle of low frequency instrumentation.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

func main() {
	const symbol = "main.doWork"
	pid, addr := getFlags()

	dlv := exec.Command(
		"dlv",
		"attach",
		strconv.Itoa(pid),
		"--headless",
		"--accept-multiclient",
		"--api-version=2",
		"--listen="+addr,
	)
	dlv.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	err := dlv.Start()
	fatalerror("Error in staring delve", err)
	defer dlv.Process.Signal(os.Interrupt)

	waitToBeUp(addr)

	client := rpc2.NewClient(addr)
	client.Continue()
	defer func() {
		client.Halt()
		client.Detach(false)
	}()

	locations, err := client.FindLocation(api.EvalScope{
		GoroutineID: -1,
	}, symbol)
	fatalerror("Error when finding locations", err)
	if len(locations) == 0 {
		log.Fatalf("No locations found for symbol: %s", symbol)
	}
	if len(locations) != 1 {
		log.Fatalf("Too many locations found for symbol: %s (%d)", symbol, len(locations))
	}
	if locations[0].PC == 0 {
		log.Fatalf("Invalid memory address for symbol: %s (0)", symbol)
	}
	pc := locations[0].PC
	bp := &api.Breakpoint{
		Name:      "myAwesomeBreakpoint",
		Addr:      pc,
		Variables: []string{"counter"},
	}

	var prev int64
	p := message.NewPrinter(language.English)
	for {
		if timeToExit() {
			return
		}

		_, err = client.Halt()
		if err != nil {
			log.Printf("Error when halting: %s", err)
			return
		}

		_, err := client.CreateBreakpoint(bp)
		if err != nil {
			log.Printf("Error when creating breakpoint: %s", err)
			return
		}

		stateCh := client.Continue()

		var state *api.DebuggerState
		select {
		case state = <-stateCh:
		case <-time.After(3 * time.Second):
			log.Print("Unable to hit breakpont after 3 seconds")
			return
		}
		if state.Err != nil {
			log.Printf("There was a problem after the breakpoint was hit: %s", state.Err)
			return
		}

		_, err = client.ClearBreakpointByName(bp.Name)
		if err != nil {
			log.Printf("Error clearing breakpoints: %s", err)
			return
		}

		client.Continue()

		count, err := strconv.ParseInt(state.CurrentThread.BreakpointInfo.Variables[0].Value, 10, 64)
		if err != nil {
			log.Printf("Unable to convert value to int: %s", err)
			return
		}
		p.Printf("counter: %d\t(%d ops/s)\n", count, count-prev)
		prev = count

		time.Sleep(time.Second)
	}
}

func getFlags() (int, string) {
	var (
		pid  int
		addr string
	)
	flag.IntVar(&pid, "pid", -1, "pid of the process you want to trace")
	flag.StringVar(&addr, "addr", "127.0.0.1:8181", "address to have delve bind to")
	flag.Parse()
	if pid == -1 {
		log.Fatal("--pid not set")
	}
	return pid, addr
}

func waitToBeUp(addr string) {
	done := time.After(5 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		select {
		case <-done:
			log.Fatalf("Stuck waiting for %q to be up: %s", addr, err)
		default:
		}
	}
}

func fatalerror(msg string, err error) {
	if err != nil {
		log.Fatalf(msg+": %s", err)
	}
}

var sigint = make(chan os.Signal, 1)

func init() {
	signal.Notify(sigint, os.Interrupt)
}

func timeToExit() bool {
	select {
	case <-sigint:
		return true
	default:
		return false
	}
}
