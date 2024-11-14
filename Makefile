obj-m := intel-uintr.o
intel-uintr-objs := src/init.o

KERNELDIR ?= /usr/src/linux-headers-$(uname -r)/include/
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean


