# Duplicate Address Detection (xdp)
This program listen for `arp response` packets to find duplicate ips announcements.

## Instructions
1. Build the program:
```shell
make
```
2. Run the program:
```shell
./xdp_dad
```
3. Bind the xdp prog to the if:
```shell
bpftool prog list # get program id
ip link show # get if name
bpftool net attach xdp id <prog_id> dev <if_name>
```
3. Build and run the arp req program:
```shell
make arpinger
./arpinger <if_name>
```
4. Check the output:
```shell
bpftool prog trace
```
