# Makefile for sensitaint

CXX = g++
CXXFLAGS = -O2 -std=c++17 -Wall -Wextra

TARGET = sensitaint
SRC = sensitaint.cc

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
