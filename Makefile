OBJECTS   = huobj.o hulib.o pcfx-cdlink.o bincat.o
OUTPUT    = huobj hulib pcfx-cdlink bincat
TARGETS   = $(OUTPUT)
ifeq ($(OS),Windows_NT)
LIBS     += -lws2_32
endif
CFLAGS   += -O3 $(INCLUDE)
LDFLAGS  += -s
CLEANED   = $(OBJECTS) $(TARGETS)
CC        = gcc

.PHONY: all clean install

all: $(OBJECTS) $(TARGETS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

hulib: hulib.o
	$(CC) $(LDFLAGS) hulib.o -o $@ $(LIBS)
huobj: huobj.o
	$(CC) $(LDFLAGS) huobj.o -o $@ $(LIBS)
pcfx-cdlink: pcfx-cdlink.o
	$(CC) $(LDFLAGS) pcfx-cdlink.o -o $@ $(LIBS)
bincat: bincat.o
	$(CC) $(LDFLAGS) bincat.o -o $@ $(LIBS)
clean:
	$(RM) $(CLEANED)
install: $(TARGETS)
	mkdir -p $(DSTDIR)/
	cp $(TARGETS) $(DSTDIR)/
