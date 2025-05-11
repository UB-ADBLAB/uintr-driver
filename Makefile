obj-m := intel-uintr.o
intel-uintr-objs := src/init.o src/fops.o src/state.o src/proc.o src/uitt.o src/msr.o src/logging/monitor.o src/irq.o src/trace/sched.o src/checks.o src/mappings/id_mapping.o src/mappings/uitt_mapping.o src/handlers.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build/
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	mv ./compile_commands.json ./compile_commands.json.bak
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	mv ./compile_commands.json.bak ./compile_commands.json

load: all
	sudo insmod intel-uintr.ko
	sudo chmod 666 /dev/uintr

test:
	gcc -g -mgeneral-regs-only -muintr -pthread tests/new_pinned.c -o pinned
