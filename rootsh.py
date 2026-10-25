#!/usr/bin/env python3
"""Attach to the root shell that GhostLock-OWW212 leaves on the watch.

Run after rootnow.sh has fired:  python rootsh.py ["cmd1" "cmd2" ...]
With no arguments it gives an interactive root shell; with arguments it runs
them non-interactively and prints the output.
"""
import os, socket, subprocess, sys, threading, time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

PORT = 25555
ADB = os.environ.get("ADB", r"C:\platform-tools\adb.exe")
if not os.path.exists(ADB):
    ADB = "adb"  # fall back to whatever is on PATH


def forward():
    subprocess.run([ADB, "forward", f"tcp:{PORT}", f"tcp:{PORT}"],
                   check=False, capture_output=True)


def session(cmds):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    except OSError as e:
        print(f"[x] cannot reach the root daemon on 127.0.0.1:{PORT}: {e}")
        print("    Nothing is rooted on this boot - run:  root.bat")
        return 1
    s.settimeout(4)
    buf = []
    closed = threading.Event()
    got = threading.Event()

    def pump():
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                # An idle shell sends nothing, and a rooted prompt sitting quiet
                # for more than settimeout() is the NORMAL case -- treating this
                # as EOF killed every interactive session after 4 seconds while
                # the watch stayed perfectly rooted.
                continue
            except OSError:
                break
            if not d:
                break
            got.set()
            sys.stdout.write(d.decode(errors="replace"))
            sys.stdout.flush()
            buf.append(d)
        closed.set()

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    if not got.wait(5.0):
        print("[x] the daemon accepted the connection but sent nothing, then"
              " closed it - the watch rebooted since the fire. Run:  root.bat")
        s.close()
        return 1
    time.sleep(0.7)
    if cmds:
        for c in cmds:
            s.sendall((c.rstrip("\n") + "\n").encode())
            time.sleep(0.8)
        time.sleep(1.2)
        s.close()
        return 0
    print("--- interactive root shell (Ctrl-C to leave; the daemon stays up) ---")
    try:
        while not closed.is_set():
            line = input()
            s.sendall((line + "\n").encode())
            time.sleep(0.35)
    except (KeyboardInterrupt, EOFError):
        pass
    if closed.is_set():
        print("[*] root shell closed (you typed exit, or the watch rebooted)")
    s.close()
    return 0


if __name__ == "__main__":
    forward()
    sys.exit(session(sys.argv[1:]))
