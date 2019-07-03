---
title: "Automating Delve"
date: 2019-06-28T09:21:57-06:00
description: |
    How to write programs that use Delve's API to provide powerful and
    effective instrumentation.
---

In my [last post][last-post], we discussed the different forms of
instrumentation and how dynamic instrumentation can be useful. Let's
investigate how we might use debuggers to dynamically instrument live systems.

## Debuggers and ptrace

Debuggers are awesome! This is how I feel when I start a debugger:

<img src="/images/gdb.png" data-animated-src="/images/gdb.gif" class="hover-gif" />

Most of the functionality of a debugger is implemented by the [ptrace][ptrace]
syscall. This syscall allows a "tracer" process (the debugger) to control a
"tracee" process (your go program). You can intercept the tracee's signals and syscalls, read
and write to its registers and memory and single step through the program.

Since the debugger can write to the memory of the tracee, this allows it to
set breakpoints that will suspend execution of the tracee once they are hit.
We can then inspect the state of the tracee, allowing us to add arbitrary
insturmentation logic. It is super interesting how this works. To set a
breakpoint the debugger:

1. Saves a copy of the instruction from the tracee's memory where the
   breakpoint should go
1. Writes a trap instruction (a software interrupt) on top of the original
   instruction
1. When this trap instruction is executed, the tracee is suspended and the
   kernel's interrupt handler will get called, ultimately allowing the
   debugger to take control

When you tell the debugger to continue it:

1. Writes the original instruction back over the trap
1. Sets the tracee's program counter register to that memory address
1. Single steps the tracee to execute that instruction
1. Writes the trap back (so it will fire next time)
1. Resumes execution of the tracee

So cool! And you thought debuggers were magic!

This animation demonstrates the overall flow of what happens when you hit a
breakpoint:

<img src="/images/ptrace-breakpoint.png" data-animated-src="/images/ptrace-breakpoint.gif" class="hover-gif" />

As you can see, when the debugger is running, your code is suspended. That is
important to keep in mind.

## Suspended Execution

The major problem with using debuggers to add instrumentation to a running
process is suspended execution. In a production environment, you might not be
able to stop the process to inspect its state. Additionally, debuggers are
normally blocked on user input, so interacting with your process in this way
will prevent your process from running and doing useful work.

We can try to minimize the time we are in a suspended state by automating the
debugger. Delve exposes a JSON-RPC API that we can use to drive it. They even
provide their [own Go client][delve-api-client]. So helpful! This is a
technique I've used in the past and it works surprisingly well for a lot of
use cases.

Let's create a test program that requires dynamic instrumentation. We can then
write a program that automates delve to add the instrumentation we want.

Note: The full source code for this experiment can be [found
here][automating-delve-src].

Our test program is just a hot loop that will increment a counter:

```go
var counter int64

//go:noinline
func doWork() {
	counter++
}

func main() {
	fmt.Println("This is a blackbox. Read my counter.")
	for {
		doWork()
	}
}
```

The function we are instrumenting is trivial so we add the `noinline` pragma
to prevent inlining. In real-world situations, this likely isn't necessary and
if your function was indeed inlined there are ways of working around this.

Let's add instrumentation to periodically read this global counter.

First, we need to launch delve in a headless mode and attach to our process:

```go
dlv := exec.Command(
	"dlv",
	"attach",
	strconv.Itoa(pid),
	"--headless",
	"--accept-multiclient",
	"--api-version=2",
	"--listen="+addr,
)
dlv.Start()
```

This starts up delve. Delve then attaches to the process, suspends its execution, and
starts a listener on the address we provided. This will allow us to communicate
with delve and send it API commands.

Next, we need to wait for the listener to be up:

```go
waitToBeUp(addr)
```

This function attempts to dial the address multiple times. If it hasn't come
up in 5 seconds it will exit with an error:

```go
func waitToBeUp(addr string) {
	done := time.After(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
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
```

Now that we can connect to the debugger we can create our client:

```
client := rpc2.NewClient(addr)
client.Continue()
defer func() {
	client.Halt()
	client.Detach(false)
}()
```

The first thing the client needs to do is to tell the debugger to continue the
process. This makes sure it isn't suspended for longer than is needed durring
this setup phase. We then defer some cleanup routines to detach the debugger
safely from the process when our controller exits.

We now need to find what instruction to instrument. We know our function name
is `doWork`. All symbol names in Go binaries are fully qualified so the symbol
name for `doWork` is `main.doWork`. We can ask delve to resolve this
information for us:

```go
locations, _ := client.FindLocation(api.EvalScope{
	GoroutineID: -1,
}, "main.doWork")
pc := locations[0].PC
```

Now that we know the address of our function we can create our breakpoint:

```go
bp := &api.Breakpoint{
	Name:      "myAwesomeBreakpoint",
	Addr:      pc,
	Variables: []string{"counter"},
}
```

Along with the memory address of our function, this contains a friendly
name and a variable we would like to read when the breakpoint is hit.

We are now ready to start making some measurements. Here is the code to do so:

```go
for {
	client.Halt()
	client.CreateBreakpoint(bp)
	state := <-client.Continue()
	client.ClearBreakpointByName(bp.Name)
	client.Continue()

	counter := state.CurrentThread.BreakpointInfo.Variables[0].Value
	fmt.Printf("counter: %s", counter)

	time.Sleep(time.Second)
}
```

Let's break this down. First, we tell delve to halt the process, this is needed
to run commands like `CreateBreakpoint` which will write the trap instruction.
We then call `Continue` which gives us a channel. This channel will block until
the breakpoint is hit. Once it is hit we can grab the debugger state, clear
the breakpoint, and continue again. This avoids the breakpoint firing on every
invocation of `doWork`. We can now process the `counter` value and sleep.

Let's run this and see what happens!

<video controls>
    <source src="/video/counter-lowhz.mp4" type="video/mp4">
</video>

On the left you see the counter program running. I add some additional
instrumentation to output the counter state and increment rate.  On the right
is our controller process that spawns delve You can see that when
instrumentation is added the rate is barely affected.

Pretty cool stuff! Unfortunately, this technique only works for processing
events at a low frequency. In this situation, we are hitting a breakpoint only
once every second. What if we tried to sample every invocation of `doWork`?

<video controls>
    <source src="/video/counter-highhz.mp4" type="video/mp4">
</video>

Ouch! That is quite the performance hit! There are a number of reasons this
has such a large impact on performance. There is a lot of cost in context
switching between the process, kernel, and debugger. Additionally, the time
the process is suspended is small but it adds up to significant overhead when
the breakpoints are firing frequently.

In the next post, we will investigate using uprobes and BPF to
instrument at a high rate!

[last-post]: /posts/instrumentation-and-go/
[gdb]: /images/gdb.gif
[ptrace]: http://man7.org/linux/man-pages/man2/ptrace.2.html
[delve-api-client]: https://godoc.org/github.com/go-delve/delve/service/rpc2#RPCClient
[automating-delve-src]: https://github.com/jasonkeene/wat/tree/master/src/automating-delve
