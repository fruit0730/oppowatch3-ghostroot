"""Run one command through the rooted daemon (127.0.0.1:25555) and wait for it.

rootsh.py is for interactive/text use; this waits for a completion marker so a
long `dd` (up to 3.5 GB for super) can be driven from a shell script.
"""
import socket, sys, time

PORT = 25555


def run(cmd, timeout=5400):
    # The sentinel must differ between "the terminal echoing my command" and "the
    # shell's own output": an interactive sh echoes the line verbatim, so the
    # marker is only recognisable once $((...)) has been expanded.
    marker = "QEND%d" % (int(time.time() * 1000) % 1000000)
    done = ("%s_%d" % (marker, 3 * 14)).encode()
    s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    s.settimeout(120)
    s.sendall(("%s\necho %s_$((3*14)) rc=$?\n" % (cmd, marker)).encode())
    buf = b""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            d = s.recv(65536)
        except socket.timeout:
            continue
        except Exception:
            break
        if not d:
            break
        buf += d
        if done in buf:
            time.sleep(0.4)
            try:
                buf += s.recv(4096)
            except Exception:
                pass
            break
    try:
        s.close()
    except Exception:
        pass
    return buf.decode(errors="replace")


if __name__ == "__main__":
    to = int(sys.argv[1]) if sys.argv[1].isdigit() else 5400
    cmd = " ".join(sys.argv[2:] if not sys.argv[1].isdigit() else sys.argv[2:])
    sys.stdout.write(run(cmd, to))
