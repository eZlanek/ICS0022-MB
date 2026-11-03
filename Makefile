CXX ?= c++
CPPFLAGS += $(shell pkg-config --cflags libsodium)
CXXFLAGS += -std=c++17 -Wall -Wextra -Wpedantic -O2
LDLIBS += $(shell pkg-config --libs libsodium)
pm: main.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) main.cpp -o pm $(LDLIBS)
.PHONY: clean
clean:
	rm -f pm
