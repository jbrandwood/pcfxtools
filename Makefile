OBJECTS   = huobj.o hulib.o pcfx-cdlink.o bincat.o
OUTPUT    = huobj hulib pcfx-cdlink bincat
TARGETS   = $(OUTPUT)
LIBS     += 
CFLAGS   += -O3 $(INCLUDE)
LDFLAGS  += $(LIBS) -g
CLEANED   = $(OBJECTS) $(TARGETS)

.PHONY: all clean

all: $(OBJECTS) $(TARGETS)
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

hulib: hulib.o
	$(CC) $(LDFLAGS) hulib.o -o $@
huobj: huobj.o
	$(CC) $(LDFLAGS) huobj.o -o $@
pcfx-cdlink: pcfx-cdlink.o
	$(CC) $(LDFLAGS) pcfx-cdlink.o -o $@
bincat: bincat.o
	$(CC) $(LDFLAGS) bincat.o -o $@
clean:
	$(RM) $(CLEANED)
