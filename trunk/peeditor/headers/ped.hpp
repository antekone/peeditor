/*
 * File:   ped.hpp
 * Author: antek
 *
 * Created on 21 lipiec 2008, 21:00
 */

#ifndef _PED_HPP
#define	_PED_HPP

#include <stdlib.h>
#include <stdarg.h> // va_start / va_end
#include <unistd.h>
#include <string.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cassert>
#include <iomanip>
#include <vector>
#include <memory> // auto_ptr
using namespace std;

#include "types.hpp"
#include "Log.hpp"
#include "Alloc.hpp"
#include "RVAConverter.hpp"

void log(int, string, ...);

#define TESTS

#endif
