/*
 * Log.h
 *
 *  Created on: 2008-08-08
 *      Author: antek
 */

#ifndef LOG_H_
#define LOG_H_

class Log {
private:
	Log();

public:
	virtual ~Log();

	static void info(char *);
};

#endif /* LOG_H_ */
