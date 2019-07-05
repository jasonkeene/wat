package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

const source string = `
#include <uapi/linux/ptrace.h>

BPF_ARRAY(count, u64, 1);

int read_counter(struct pt_regs *ctx) {
	u64 *counterPtr = (u64 *)%d;

	int first = 0;
	u64 zero = 0, *val;
	val = count.lookup_or_init(&first, &zero);

	u64 counter;
	bpf_probe_read(&counter, sizeof(counter), counterPtr);
	*val = counter;

	return 0;
}
`

func main() {
	counterAddr := lookupSym("/tmp/counter", "main.counter")

	m := bpf.NewModule(fmt.Sprintf(source, counterAddr), []string{})
	defer m.Close()

	probe, err := m.LoadUprobe("read_counter")
	if err != nil {
		log.Printf("Failed to load read_counter: %s", err)
		return
	}

	err = m.AttachUprobe("/tmp/counter", "main.doWork", probe, -1)
	if err != nil {
		log.Printf("Failed to attach uprobe: %s", err)
		return
	}

	table := bpf.NewTable(m.TableId("count"), m)

	var prev, count uint64
	p := message.NewPrinter(language.English)
	for {
		data, err := table.Get([]byte{0})
		if err != nil {
			log.Printf("Failed to read from table: %s", err)
			return
		}

		count = binary.LittleEndian.Uint64(data)
		p.Printf("counter: %d\t(%d ops/s)\n", count, count-prev)
		prev = count
		time.Sleep(time.Second)
	}
}

func lookupSym(path, name string) uint64 {
	f, err := elf.Open(path)
	if err != nil {
		log.Fatalf("Unable to open: %s %s", path, err)
	}
	syms, err := f.Symbols()
	if err != nil {
		log.Fatalf("Unable to read syms: %s", err)
	}
	for _, s := range syms {
		if s.Name == name {
			return s.Value
		}
	}
	log.Fatalf("Unable to find sym: %s %s", path, name)
	return 0
}
