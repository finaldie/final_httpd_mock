TARGET = test
BIN_PATH = bin

INCLUDE_PATH = ../include
LIBS_PATH = ../lib64
INSTALL_PATH = bin

CC = gcc
INC = -I$(INCLUDE_PATH) -I../src
LL = -L$(LIBS_PATH)

LIBS = -lfhash \
	   -lfmempool \
	   -lpthread \
	   -lflock \
	   -lflog \
	   -lfev \
	   -lftimer \
	   -lfnet \
	   -lftu \
	   -lflist \
	   -lfmbuf \
	   -lfconf \
	   -lfpcap_conv \
	   -lfhash \
	   -lpcap \
	   -lrt

SRCS = main.c \
       t_tcp.c \
       ../src/http_load_pcap.c

COPY_FILES =

DEPS = $(patsubst %.c,%.d,$(SRCS))
OBJS = $(patsubst %.c,%.o,$(SRCS))
CFLAGS = -Wall -Wextra -Werror -g -O2

all: $(TARGET)
$(TARGET):$(OBJS) $(DEPS)
	$(CC) $(CFLAGS) $(INC) $(LL) -o $(TARGET) $(OBJS) $(LIBS)


%.d: %.c
	$(CC) $(INC) -MM $< > $@
%.o: %.c 
	$(CC) $(CFLAGS) $(INC) -c $< 

check:
	./$(TARGET)

.PHONY:clean
clean:
	rm -f $(DEPS) $(OBJS) $(TARGET)

help:
	@echo "The information represents in the program:"
	@echo "Final executable name: $(TARGET)"
	@echo "Source files: $(SRCS)"
	@echo "Object files: $(OBJS)"
depend:$(DEPS)
	@echo "Dependencies are now up-to-date"
-include $(DEPS)
