#!/usr/bin/env python

import frida
import sys

scriptText = """
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
    var ctrPtr = ptr(resolveAddr("main.counter"));

    function rx() {
        var op = recv("setCounter", function (message) {
            ctrPtr.writeS64(message.value);
        });
        op.wait();
        setTimeout(rx, 0);
    }
    setTimeout(rx, 0);
"""

def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script(scriptText)
    script.load()
    try:
        while True:
            val = raw_input("set counter to: ")
            if val == "":
                break
            script.post({"type": "setCounter", "value": int(val)})
    except KeyboardInterrupt:
        pass
    session.detach()

if __name__ == "__main__":
    main(sys.argv[1])
