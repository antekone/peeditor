/*
 * Log.cpp
 *
 *  Created on: 2008-08-08
 *      Author: antek
 */

#include "ped.hpp"
#include "Log.hpp"

Log::Log() {
	// TODO Auto-generated constructor stub

}

Log::~Log() {
	// TODO Auto-generated destructor stub
}

void Log::info(char *text) {
	cout << INFO << text << endl;
}
