# Hello World (XDP)

## Instructions
1. Run `make`
2. Pin the program
```shell
bpftool prog load .output/hello_world.bpf.o /sys/fs/bpf/hello_world
```
3. Get prog id (the program will have the name of the main function as the name)
```shell
bpftool prog list
```
4. Get interface name
```shell
ip link show
```
5. Attach to interface
```shell
bpftool net attach xdp id <bpf_prog_id> dev <if_name>
```
6. Read logs
```shell
bpftool prog tracelog
```

## Alt
Altrenatively you can use this command to skip pinning the program
```shell
ip link set dev <if_name> xdp obj .output/hello_world.bpf.o sec xdp
```