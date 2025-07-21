#pragma once
#include <chrono>
class Timer
{
private:
  std::chrono::_V2::high_resolution_clock::time_point startp;
  std::chrono::_V2::high_resolution_clock::time_point endp;

public:
  void start();

  void stop();
  unsigned int get_elapsed(bool useStop = false, int secondType = 0);
};