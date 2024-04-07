# Compiler
CC := g++
LDFLAGS=-lpcap
# Compiler flags
CFLAGS := -std=c++20 -g

# Source files
SRCS := main.cpp arg_parser.cpp connection.cpp
# Object files
OBJS := $(SRCS:.cpp=.o)

# Header files
HDRS := $(wildcard *.h)

# Target executable
TARGET := ipk-sniffer

# Default target
all: $(TARGET)

# Rule to compile object files
%.o: %.cpp $(HDRS)
	$(CC) $(LDFLAGS) $(CFLAGS) -c $< -o $@

# Rule to link object files and create the executable
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o $@

# Clean rule
clean:
	rm -f $(OBJS) $(TARGET)

run:
	make
	./ipk-sniffer 
	