
CC=gcc
CFLAGS=-I.
DEPS = protocol_util.h
OBJ = protocol_util.o wired_ethernet_protocol_format.o wireless_ethernet_protocol_format.o internet_protocol_format.o address_resolution_protocol.o internet_control_messaging_protocol.o main.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

