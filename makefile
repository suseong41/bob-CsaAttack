CXX = g++
CXXFLAGS = -std=c++20
LDLIBS=-lpcap

all: csa-attack

csa-attack: main.o radiotap.o wireless.o
	$(CXX) main.o radiotap.o wireless.o $(LDLIBS) -o airodump

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

radiotap.o: radiotap.cpp radiotap.h
	$(CXX) $(CXXFLAGS) -c radiotap.cpp -o radiotap.o   
	
wireless.o: wireless.cpp wireless.h
	$(CXX) $(CXXFLAGS) -c wireless.cpp -o wireless.o

clean:
	rm -f airodump *.o