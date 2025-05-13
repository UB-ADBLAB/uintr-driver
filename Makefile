obj-m := intel-uintr.o
intel-uintr-objs := src/init.o src/fops.o src/state.o src/proc.o src/uitt.o src/msr.o src/logging/monitor.o src/irq.o src/trace/sched.o src/checks.o src/mappings/id_mapping.o  src/handlers.o src/mappings/proc_mapping.o

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
	gcc -g -mgeneral-regs-only -muintr -pthread ./tests/new_pinned.c -o pinned

test_migration:
	gcc -g -mgeneral-regs-only -muintr -pthread ./tests/new_migration.c -o migration

test_two_sender:
	gcc -g -mgeneral-regs-only -muintr -pthread ./tests/two_sender_unpinned.c -o two_sender_unpinned

test_one_sender:
	gcc -g -mgeneral-regs-only -muintr -pthread ./tests/one_sender_unpinned.c -o one_sender_unpinned
