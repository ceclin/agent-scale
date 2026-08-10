#!/usr/bin/env python3
import argparse
import socket
import struct
import threading
import time


def recv_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def echo_stream(stream):
    with stream:
        while data := stream.recv(65536):
            stream.sendall(data)


def serve():
    tcp = socket.create_server(("127.0.0.1", 0))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    print(tcp.getsockname()[1], udp.getsockname()[1], flush=True)

    def tcp_loop():
        while True:
            stream, _ = tcp.accept()
            threading.Thread(target=echo_stream, args=(stream,), daemon=True).start()

    def udp_loop():
        while True:
            data, source = udp.recvfrom(65535)
            udp.sendto(data, source)

    threading.Thread(target=tcp_loop, daemon=True).start()
    threading.Thread(target=udp_loop, daemon=True).start()
    threading.Event().wait()


def round_trip(stream, size):
    remaining = size
    block = bytes(range(256)) * 256
    started = time.monotonic()
    while remaining:
        payload = block[: min(remaining, len(block))]
        stream.sendall(payload)
        if recv_exact(stream, len(payload)) != payload:
            raise RuntimeError("echo payload mismatch")
        remaining -= len(payload)
    return time.monotonic() - started


def socks_negotiate(stream):
    stream.sendall(b"\x05\x01\x00")
    if recv_exact(stream, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 no-auth negotiation failed")


def domain_address(host, port):
    encoded = host.encode("ascii")
    return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port)


def read_address(stream):
    address_type = recv_exact(stream, 1)[0]
    if address_type == 1:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(stream, 4))
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(stream, 16))
    elif address_type == 3:
        host = recv_exact(stream, recv_exact(stream, 1)[0]).decode("ascii")
    else:
        raise RuntimeError(f"unknown SOCKS address type {address_type}")
    return host, struct.unpack("!H", recv_exact(stream, 2))[0]


def socks_reply(stream):
    version, status, reserved = recv_exact(stream, 3)
    if (version, status, reserved) != (5, 0, 0):
        raise RuntimeError(f"SOCKS request failed with status {status}")
    return read_address(stream)


def fixed(proxy_port, size):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as stream:
        elapsed = round_trip(stream, size)
    print(f"{size / 1048576:.0f} MiB in {elapsed:.2f}s")


def socks_connect(proxy_port, target_port):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as stream:
        socks_negotiate(stream)
        stream.sendall(b"\x05\x01\x00" + domain_address("localhost", target_port))
        socks_reply(stream)
        round_trip(stream, 1024 * 1024)


def socks_udp(proxy_port, target_port):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as control:
        socks_negotiate(control)
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        relay = socks_reply(control)
        payload = b"agent-scale UDP"
        target = b"\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port)
        packet = b"\x00\x00\x00" + target + payload
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(10)
        udp.sendto(packet, relay)
        response, _ = udp.recvfrom(65535)
        if response[:3] != b"\x00\x00\x00":
            raise RuntimeError("invalid SOCKS UDP response")
        view = memoryview(response[3:])
        address_type = view[0]
        offset = 1 + (4 if address_type == 1 else 16)
        offset += 2
        if bytes(view[offset:]) != payload:
            raise RuntimeError("SOCKS UDP payload mismatch")


parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest="command", required=True)
sub.add_parser("server")
fixed_parser = sub.add_parser("fixed")
fixed_parser.add_argument("proxy_port", type=int)
fixed_parser.add_argument("--size", type=int, default=1024 * 1024)
connect_parser = sub.add_parser("socks-connect")
connect_parser.add_argument("proxy_port", type=int)
connect_parser.add_argument("target_port", type=int)
udp_parser = sub.add_parser("socks-udp")
udp_parser.add_argument("proxy_port", type=int)
udp_parser.add_argument("target_port", type=int)
args = parser.parse_args()

if args.command == "server":
    serve()
elif args.command == "fixed":
    fixed(args.proxy_port, args.size)
elif args.command == "socks-connect":
    socks_connect(args.proxy_port, args.target_port)
elif args.command == "socks-udp":
    socks_udp(args.proxy_port, args.target_port)
