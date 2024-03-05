CC=g++
CFLAGS= -std=c++11 -O2 -Wall
LDFLAGS=-static
SOURCES=ModelEncryptionGOST.cpp
HEADERS=block_functions.h  cipher_base.h  cipher_modes.h  common.h  kuznyechik.h  kuznyechik_tables.h  magma.h  message.h  test.h
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=test

all: $(SOURCES) $(HEADERS) $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

clean:
	rm $(EXECUTABLE)
