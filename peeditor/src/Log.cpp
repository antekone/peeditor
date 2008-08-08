/*
 * Log.cpp
 *
 *  Created on: 2008-08-08
 *      Author: antek
 */

#include "ped.hpp"
#include "Log.hpp"

Log::Log() {
}

Log::~Log() {
}

void Log::info(char *text) {
	cout << INFO << text << endl;
}
