OBJECTS   = huobj.o hulib.o
OUTPUT    = huobj hulib
TARGETS   = $(OUTPUT)
LIBS      = 
CFLAGS    = -O3 $(INCLUDE)
LDFLAGS   = $(LIBS) -g
CLEANED   = $(OBJECTS) $(TARGETS)

.PHONY: all clean

all: $(OBJECTS) $(TARGETS)
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

hulib: hulib.o
	$(CC) $(LDFLAGS) hulib.o -o $@
huobj: huobj.o
	$(CC) $(LDFLAGS) huobj.o -o $@
clean:
	$(RM) $(CLEANED)

