/*
 * User.h
 *
 *  Created on: 26.04.2010
 *      Author: blacksmith
 */

#ifndef USER_H_
#define USER_H_
#include <stdint.h>
#include <stdlib.h>

class User
{
public:
	int userid;
	double balance;
	int doublepaytime;
	int showcat;
	int advside;
	int pornosite;
	int user_location;
	int moder;
	int refucur;
	char * remote_addr;
	uint32_t remoteAddr;
	User();
	virtual ~User();
};

#endif /* USER_H_ */
