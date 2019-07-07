---
title: "Uprobes and BPF"
date: 2019-07-05T21:23:27-06:00
draft: true
description: |
    See how to use uprobes, BPF, bpftrace, BCC, and gobpf for performant
    dynamic instrumentation.
---

Today's post is about two really awesome technologies: uprobes and BPF. [Last
week][last-post] we discussed using ptrace and delve to dynamically instrument
Go programs. This is a very powerful technique but it is not suited for
high-frequency events. uprobes and BPF can be used at much higher frequencies.

Unlike ptrace, both of these technologies are Linux specific. If you run on
other platforms you can find similar capabilities in tools like
[DTrace][dtrace]. Most of my experience running Go code in production, where
performance matters, is on Linux. If you are developing on other platforms (as
I do) I recommend using [VirtualBox][virtualbox] and [Vagrant][vagrant]. An
example [Vagrantfile][vagrantfile] is provided with the [full source
code][source] for this post. This will provision an ubuntu box with bpftrace
and bcc installed and ready to use.

To demonstrate how to write programs using uprobes and BPF, I will be using a
few tools and libraries: [bpftrace][bpftrace], [BCC][bcc], and [gobpf][gobpf].
No prior knowledge of these is required.

Let's get started!

## Uprobes

Uprobes is a capability of the Linux kernel to add instrumentation to any
instruction in user-space. It functions in a similar way to ptrace. It uses
the same software interrupt mechanism and the uprobe handlers can even receive
`pt_regs` as an argument which is the ptrace registers struct. Where it
differs significantly from ptrace is that it operates on files vs processes.
You set a uprobe at a certain offset in an executable file. This might seem
strange, however, it offers some benefits. For instance, you can instrument
multiple instances of a program at once. You can also instrument a .so that is
dynamically linked to by multiple other programs. You don't need to instrument
these programs individually. A good example would be the function `accept`
which is defined in libc. Almost all programs that accept connections would
use this function to do so. uprobes also provides a filtering mechanism for
reducing the set of events quickly. This can be used to filter out events from
programs you are not interested in.

Let's see what the execution flow looks like for uprobes:

// TODO: create graphic to demostrate uprobes flow

There are a few options for creating the actual uprobe handler that runs in
the kernel. You could write a kernel module, but this has massive downsides in
safety and complexity. This is where BPF can help us.

## BPF

BPF is the Berkeley Packet Filter. It allows you to run little programs to
filter packets inside the kernel. Running these filters inside the kernel is a
good idea since copying the packet data and context switching with a user
space process is expensive.

If you have ever used tcpdump you have used BPF. You can actually
see the BPF bytecode that tcpdump generates by adding `-d` flag:

```
$ tcpdump -d port 80 or port 443
(000) ldh      [12]
(001) jeq      #0x86dd          jt 2    jf 11
(002) ldb      [20]
(003) jeq      #0x84            jt 6    jf 4
...
```

The expression `port 80 or port 443` was compiled into this bytecode. The
bytecode then gets loaded into the kernel where it compiles it into native
instructions.

You might be wondering, "why are we talking about packets?" Well, these little
BPF programs can do more than just filter packets. The BPF capability of Linux
has been extended over the past few years and you can now attach these
programs to uprobes to handle events that occur in your programs.

Of course, we need some help in creating these BPF programs. We need to write
them in some language and they need to get compiled into the BPF bytecode,
injected into the kernel, attached to our uprobes, and detached when we are
done. Here is an overview of the process:

// TODO: create graphic to demostrate bpf flow

Fortunately, there is an amazing framework called BCC that does all of this for
us. There are two great frontends for BCC that I have used to instrument Go
programs: bpftrace and gobpf. Let's check them out!

## bpftrace

bpftrace is a relatively new tool. It provides a high-level language for
writing these BPF programs and is focused on the use case of tracing. Let's
take the counter program from the [previous post][last-post] and see if we can
instrument every invocation of `doWork` and read the global counter it is
incrementing.  This is what that looks like:

```bpftrace
uprobe:/tmp/counter:"main.doWork" {
    @ = *uaddr("main.counter");
}

interval:s:1 {
    printf("counter: %d\t %d ops/sec\n", @, @-@prev);
    @prev = @;
}
```

This language is far from Go. The semantics can be a bit confusing and it
takes some getting used to. Let's break it down bit by bit.

```bpftrace
uprobe:/tmp/counter:"main.doWork"
```

First, we declare that we want to attach a uprobe to our binary file
`/tmp/counter`. We also provide the symbol to attach to the uprobe:
`"main.doWork"`. Because Go's symbol names can contain strange characters like
periods, slashes, and unicode characters we need to wrap our symbol name in
quotes to tell bpftrace to treat this as a literal symbol name.


```bpftrace
@ = *uaddr("main.counter");
```

Inside the curly braces is the code that will run when this uprobe is fired.
First, we look up the address of where our counter is located. Since this is
static, this will actually be done only once, before the BPF code is compiled.
This won't actually run in the BPF program itself. What is ran in the BPF
program is the dereference of this address and the copy of that value into a
map `@`.

Maps are a way to communicate data between the BPF program running in the
kernel and the bpftrace program running in user space. The lone sigil `@` is
the default map in bpftrace's language. You can have other maps with explicit
names as we'll see.

```bpftrace
interval:s:1 {
    printf("counter: %d\t %d ops/sec\n", @, @-@prev);
    @prev = @;
}
```

Finally, we trigger an event to fire every second. In the handler for this
event, we print out the counter state and compute the rate by subtracting the
previous counter state.

Let's see this run:

<video controls>
    <source src="/video/bpftrace.mp4" type="video/mp4">
</video>

Wow! Over 300,000 ops/sec. That is a lot better than the 80 ops/sec we could do
with traditional ptrace. Keep in mind that we are instrumenting every
invocation of `doWork`. This is good enough for a lot of use cases. Many
production workloads do under 300 kops/sec/thread. However, there are some
issues with this approach. First is that bpftrace is a new project and as such
its support for Go is not fully baked. I imagine this will change in the next
few years, but as it stands now, there is a lot you can not do unless you are
prepared to modify bpftrace itself. Secondly, we have to write code in some
other language and it is not always clear what this language is doing. It
would be much better to write these programs in Go.

<img src="/images/yesitis.png" data-animated-src="/images/yesitis.gif" class="hover-gif" />

## gobpf

gobpf provides Go bindings for the BCC framework. BCC allows you to compile BPF
programs that are written in C. So we get to write our user space code in Go
but the kernel bit needs to be in C. Also, since BCC itself is written in C,
the gobpf bindings use cgo. So yeah, not ideal but at least we get to write
some Go!

Let's build a Go program that will effectively do the same thing as the
bpftrace program above. The Go program will compile our BPF program that we'll
write in C, inject it into the kernel, attach a uprobe to it, and report the
resulting data. Since the C part is the most gnarly we should tackle it first!

> If it's your job to eat two frogs, it's best to eat the biggest one first.  
> -- <cite>Mark Twain</cite>

Ok, we start by declaring our string:

```go
const bpfSource = ``
```

Inside this string will be all the C source code, simple enough. Let's start
by adding one of the BCC macros that will allow us to communicate from the BCC
program to the Go program:

```c
BPF_ARRAY(count, u64, 1);
```

I chose `BPF_ARRAY` for this example but there are many options. The important
thing about this macro is that it will give us a variable `count` that will
allow us to share values of type `u64` (`uint64` in Go).

```c
int read_counter() {}
```

We can now define a function `read_counter` that will handle our uprobe
events. It will read the counter and store it in our `BPF_ARRAY`. We will need
to do a few things inside this function.

First, we need to know where in the process's memory the counter is located so
we can read it. We can declare and initializes a pointer to this address:

```c
u64 *counterPtr = (u64 *)%d;
```

Since we don't know the actual address yet let's just use `%d` and template it
out later.

Next, we will need to get a pointer into the `BPF_ARRAY`, where we will write
the counter. We can use the `lookup_or_init` function pointer that is stored
on our `count` array:

```c
int first = 0;
u64 zero = 0, *val;
val = count.lookup_or_init(&first, &zero);
```

Now that we have both the pointer to the counter in the process's memory and a
pointer to the `BPF_ARRAY` where we want to write the counter, we can just
tell BCC to copy the value over:

```c
bpf_probe_read(val, sizeof(*counterPtr), counterPtr);
```

Cool, that should be it! Enough with C, let's write some Go. First, we need to
resolve that address that we were going to template out:

```go
counterAddr := lookupSym("/tmp/counter", "main.counter")
```

We can use the `elf` package from the stdlib to open the binary and find the
address:

```go
func lookupSym(path, name string) uint64 {
	f, _ := elf.Open(path)
	syms, _ := f.Symbols()
	for _, s := range syms {
		if s.Name == name {
			return s.Value
		}
	}
	log.Fatalf("Unable to find sym: %s %s", path, name)
	return 0
}
```

This demonstrates what is awesome about using gobpf. You have all the
incredibly powerful Go packages available to you to do whatever you need.
This would have been such a pain in the neck if it wasn't in Go!

Now that we know the address for the counter, we can render the template and
use gobpf to compile the program and load it into the kernel:

```go
m := bpf.NewModule(fmt.Sprintf(bpfSource, counterAddr), nil)
```

We can now use gobpf to attach the `read_counter` handler in our BPF program
to a uprobe that is located at the `doWork` function:

```go
probe, _ := m.LoadUprobe("read_counter")
m.AttachUprobe("/tmp/counter", "main.doWork", probe, -1)
```

We can then loop forever, reading the counter from our `BPF_ARRAY` every
second and outputting that information:

```go
table := bpf.NewTable(m.TableId("count"), m)
var prev, count uint64
for {
    data, _ := table.Get([]byte{0})
    count = binary.LittleEndian.Uint64(data)
    fmt.Printf("counter: %d\t(%d ops/s)\n", count, count-prev)
    prev = count
    time.Sleep(time.Second)
}
```

When you put it all together you get the same performance as the `bpftrace`
example:

<video controls>
    <source src="/video/gobpf.mp4" type="video/mp4">
</video>

This can seem like more work for the same result, however, you get to write
your user space code in Go! This affords way more power and control than what
bpftrace provides. There are use cases for both. Typically, I will start by
writing a program using `bpftrace` and if I run into its limitations with
respect to Go, I will rewrite my program using gobpf. It is good to have
multiple options!

I hope seeing these technologies in action has piqued your interest. There is
a lot of power and performance to be had by dynamically instrumenting your
code with uprobes and BPF. I feel these technologies are super underutilized,
especially within the Go community. There are certainly rough edges with Go
support, but the more we use these tools the better they will become. If you
do run into problems make sure to file issues. I know it can seem like a
hassle but I've found the maintainers of these projects to be very helpful,
kind, and considerate.

In my next post, I will investigate using a tool called Frida to do dynamic
instrumentation entirely in user space!

[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/
[last-post]: https://wat.io/posts/automating-delve/
[dtrace]: http://dtrace.org/blogs/about/
[bpftrace]: https://github.com/iovisor/bpftrace
[bcc]: https://github.com/iovisor/bcc
[gobpf]: https://github.com/iovisor/gobpf
[vagrantfile]: https://github.com/jasonkeene/wat/tree/master/src/uprobes-and-bpf/Vagrantfile
[source]: https://github.com/jasonkeene/wat/tree/master/src/uprobes-and-bpf/
