# vboxvmi

Pure-Rust client for VBoxVMI, the introspection protocol served by a patched VirtualBox VM
process over a per-VM Unix domain socket. Used by libmicrovmi's VBoxVMI access method.

The protocol is specified in the patched VirtualBox tree (`doc/technical/VBoxVMI-protocol.md`,
branch `vmi/vboxvmi` of https://github.com/Wenzel/virtualbox). Linux only.

    VBoxManage setextradata <vm> VBoxInternal/VMI/Enabled 1   # then start the VM
    cargo run --example handshake -- <VBox user home>/vmi/<vm uuid>.sock
    cargo run --example read -- <VBox user home>/vmi/<vm uuid>.sock 0 fee00000   # RAM ranges, page status
    cargo run --example pause -- <VBox user home>/vmi/<vm uuid>.sock 5           # vCPU count, pause 5 s, resume
    cargo run --example registers -- <VBox user home>/vmi/<vm uuid>.sock 0       # vCPU 0 registers, written back
    cargo run --example events -- <VBox user home>/vmi/<vm uuid>.sock singlestep 0  # next instruction on vCPU 0

The `events` example accepts `breakpoint` instead of `singlestep` if the guest will execute
an `int3`. It clears the Intercept after one event and replies, reinjecting #BP for a breakpoint.
