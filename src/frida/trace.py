import frida
import sys

script = """
    var count = 0;

    setInterval(function () {
        send(count);
    }, 1000);

    function resolveAddr(symName) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            var syms = mods[i].enumerateSymbols();
            for (var j = 0; j < syms.length; j++) {
                if (syms[j].name === symName) {
                    return syms[j].address;
                }
            }
        }
        throw "unable to find symbol "+symName;
    }
    var doWorkAddr = resolveAddr("main.doWork");
    var ctrPtr = ptr(resolveAddr("main.counter"));

    Interceptor.attach(doWorkAddr, {
        onEnter: function () {
            count = ctrPtr.readS64();
        }
    });
"""

counter = 0

def on_message(message, data):
    global counter
    newCounter = int(message["payload"])
    rate = newCounter - counter
    counter = newCounter
    print("counter: {:,} ({:,} ops/s)".format(counter, rate))

def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script(script)
    script.on("message", on_message)
    script.load()
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    session.detach()

if __name__ == "__main__":
    main(sys.argv[1])
