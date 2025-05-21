# Path config
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCDIR ?= $(PREFIX)/include
SO_VERSION ?= 0

# Kernel module config
KERNELDIR ?= /lib/modules/$(shell uname -r)/build/
PWD := $(shell pwd)
obj-m := intel-uintr.o
intel-uintr-objs := src/init.o src/fops.o src/state.o src/proc.o src/uitt.o \
                   src/msr.o src/logging/monitor.o src/irq.o src/trace/sched.o \
                   src/checks.o src/mappings/id_mapping.o src/handlers.o \
                   src/mappings/proc_mapping.o

# User-space library configuration
USER_OBJS := src/uintrdriv.o
LIB_NAME := libuintrdriv.so

# Compiler flags
CFLAGS += -fPIC -Wall -O2
LDFLAGS += -shared -Wl,-soname,$(LIB_NAME).$(SO_VERSION)

# Test config
TEST_FLAGS := -g -mgeneral-regs-only -muintr -pthread
TEST_SRCS := $(wildcard tests/*.c)
TEST_BINS := $(patsubst tests/%.c,%,$(TEST_SRCS))

.PHONY: all module library install uninstall clean load test tests

# Main targets
all: module library

module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

library: $(LIB_NAME)

# Build the shared object
$(LIB_NAME): $(USER_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install both library and header
install: $(LIB_NAME)
	# library
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 $(LIB_NAME) $(DESTDIR)$(LIBDIR)/$(LIB_NAME).$(SO_VERSION)
	ln -sf $(LIB_NAME).$(SO_VERSION) $(DESTDIR)$(LIBDIR)/$(LIB_NAME)
	# header
	install -d $(DESTDIR)$(INCDIR)
	install -m 644 include/uintrdriv.h $(DESTDIR)$(INCDIR)/uintrdriv.h

uninstall:
	$(RM) $(DESTDIR)$(LIBDIR)/$(LIB_NAME).$(SO_VERSION) \
	      $(DESTDIR)$(LIBDIR)/$(LIB_NAME) \
	      $(DESTDIR)$(INCDIR)/uintrdriv.h

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	$(RM) $(LIB_NAME) $(USER_OBJS) $(TEST_BINS)

load: module
	sudo insmod intel-uintr.ko
	sudo chmod 666 /dev/uintr

# Generic test target
%: tests/%.c
	$(CC) $(TEST_FLAGS) $< -o $@ -L$(PWD) -luintrdriv

# Build all test executables
tests: library $(TEST_BINS)

# Individual test shortcuts
test: pinned

test_migration: migration

test_two_sender: two_sender_unpinned

test_one_sender: one_sender_unpinned
