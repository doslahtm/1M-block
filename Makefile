CXX = g++
CXXFLAGS = -lnetfilter_queue
TARGET = 1m-block

1m-block : 1m-block.o
	g++ 1m-block.o $(CXXFLAGS) -o 1m-block

1m-block.o : 1m-block.cpp
	g++ -c 1m-block.cpp




clean:
	rm $(TARGET) $(TARGET).o
