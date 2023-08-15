#include "inc/utils/time.hpp"
#include <chrono>

void Timer::start()
{
  startp = std::chrono::high_resolution_clock::now();
}

void Timer::stop()
{
  endp = std::chrono::high_resolution_clock::now();
}

unsigned int Timer::getElapsed(bool useStop, int secondType)
{
  if (useStop)
    stop();

  if (!secondType)
    return std::chrono::duration_cast<std::chrono::microseconds>(endp - startp).count();
  else
    return std::chrono::duration_cast<std::chrono::nanoseconds>(endp - startp).count();
}