obj-m += cloud_toa_sender.o
cloud_toa_sender-y := kernel/cloud_toa_sender_main.o kernel/cloud_toa_sender_map.o

ccflags-y += -I$(PWD)/include/uapi

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
