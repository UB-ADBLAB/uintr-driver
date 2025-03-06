obj-m := intel-uintr.o
intel-uintr-objs := src/init.o src/fops.o src/state.o src/proc.o src/uitt.o src/msr.o src/logging/monitor.o src/irq.o src/trace/sched.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build/
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

test_simpl:
	gcc -mgeneral-regs-only -pthread tests/simplified_pinned.c -o simplified_pinned

test_migration:
	gcc -mgeneral-regs-only -pthread tests/simplified_migration.c -o simplified_migration
