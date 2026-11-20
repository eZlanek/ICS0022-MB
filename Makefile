CXX ?= c++
CPPFLAGS += $(shell pkg-config --cflags libsodium)
CXXFLAGS += -std=c++17 -Wall -Wextra -Wpedantic -O2
LDLIBS += $(shell pkg-config --libs libsodium)

pm: main.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) main.cpp -o $@ $(LDLIBS)

pm-test: main.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DPM_TESTING main.cpp -o $@ $(LDLIBS)

unit-tests: tests/unit.cpp main.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/unit.cpp -o $@ $(LDLIBS)

.PHONY: test sanitize clean

test: pm pm-test unit-tests
	./unit-tests
	python3 test_cli.py

sanitize:
	$(CXX) $(CPPFLAGS) -std=c++17 -Wall -Wextra -Wpedantic -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined tests/unit.cpp -o unit-tests-sanitize $(LDLIBS)
	./unit-tests-sanitize
	$(CXX) $(CPPFLAGS) -std=c++17 -Wall -Wextra -Wpedantic -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -DPM_TESTING main.cpp -o pm-sanitize $(LDLIBS)
	PM_EXE=./pm-sanitize PM_TEST_EXE=./pm-sanitize python3 test_cli.py

clean:
	rm -f pm pm-test pm-sanitize unit-tests unit-tests-sanitize
