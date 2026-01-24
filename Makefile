CC = gcc
#CFLAGS = -Wall -Wextra -Wno-unused-function -O0 -static -ggdb -masm=intel -no-pie
INCLUDES := $(shell find . -type d -not -path "./.*")
CFLAGS = -Wall -Wextra -Wno-unused-function -static $(addprefix -I,$(INCLUDES))

SOURCES := $(shell find . -name '*.c' -not -path "./userfaultfd/*")
OBJECTS := $(patsubst %.c,build/%.o,$(SOURCES))
LIBS = -lpthread

exp: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@