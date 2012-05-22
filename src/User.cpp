/*
 * User.cpp
 *
 *  Created on: 26.04.2010
 *      Author: blacksmith
 */

#include "User.h"

User::User() :
	userid(0), balance(0), doublepaytime(0), showcat(0), advside(0), pornosite(
			0), user_location(0), moder(0), refucur(0), remote_addr(NULL), remoteAddr(0)
{
}

User::~User()
{
	if (remote_addr)
		free(remote_addr);
}
