all:
	make -C ..

#all: libqemu.a

qemu:
	make -C .. V=1 LINK=/bin/true
	find ../stubs/ -name "*.o" -delete
	make -C .. stubs/qmp_pc_dimm_device_list.o
	make -C .. stubs/pci-drive-hot-add.o
	make -C .. stubs/dump.o
	rm -f libqemu.a

qemu-cpu.o: qemu-cpu.c
	gcc -g -O0 -c qemu-cpu.c \
	-I../include \
	-I../target-ppc \
	-I../ppc-softmmu \
	-I../../src/include \
	-I.. \
	`pkg-config --cflags glib-2.0` \
	-o qemu-cpu.o

libqemu.a: qemu qemu-cpu.o
	rm -f libqemu.a
	ar cru libqemu.a `find .. -name "*.o"`
	ranlib libqemu.a

clean:
	make -C .. clean
	rm -f *.o *.a
