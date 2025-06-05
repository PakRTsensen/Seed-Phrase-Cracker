CC = gcc
# Add -O2 for optimization
CFLAGS = -Wall -g -std=c11 -pthread -O2
LDFLAGS = -pthread -lcrypto -lsecp256k1 # Add other crypto libs as needed
INCLUDES = -Iinclude
SRCDIR = src
OBJDIR = obj
TARGET = bip39_cracker

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

# Default target
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

.PHONY: all clean
