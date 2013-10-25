TARGET = httpd_mock
BIN_PATH = ../bin

INCLUDE_PATH = ../include
LIBS_PATH = ../lib64

CC = gcc
INC = -I$(INCLUDE_PATH)
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
	   -lfhash \
	   -lfpcap_conv \
	   -lpcap \
	   -lhttp_parser \
	   -lrt

SRCS = main.c \
       http_handlers.c \
       http_content_handler.c \
       http_chunk_handler.c \
       http_mix_handler.c \
       http_load_pcap.c \
       http_pcap_handler.c

COPY_FILES = 
	   
DEPS = $(patsubst %.c,%.d,$(SRCS))
OBJS = $(patsubst %.c,%.o,$(SRCS))

CFLAGS = -Wall -Wextra -Werror -Wno-deprecated -g -O2

all: $(TARGET)

$(TARGET): $(OBJS) $(DEPS)
	$(CC) $(CFLAGS) $(INC) $(LL) -o $(TARGET) $(OBJS) $(LIBS)

%.d: %.c
	$(CC) $(INC) -MM $< > $@
%.o: %.c 
	$(CC) $(CFLAGS) $(INC) -c $< 

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
