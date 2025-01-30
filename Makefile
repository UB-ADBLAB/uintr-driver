obj-m := intel-uintr.o
intel-uintr-objs := src/init.o src/fops.o src/state.o src/proc.o src/uitt.o src/msr.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build/
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
