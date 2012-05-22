/*
 * Variant.h
 *
 *  Created on: 26.04.2010
 *      Author: blacksmith
 */

#ifndef VARIANT_H_
#define VARIANT_H_
#include <string.h>
#include <vector>     // для std::vector<>
#include <iostream>

typedef enum
{
	T_NULL = -1, T_INT = 0, T_STRING = 1, T_ARRAY = 2,
} dataType;

class Variant;
typedef std::vector< Variant* > varvector;
typedef std::vector< Variant* >::iterator viter;

Variant * vfind(varvector *items, const char * key);

class Variant
{
public:
	dataType type;
	char * key;
	void * value;

	Variant();
	Variant(const char *key);
	Variant(const char *key, int val);
	Variant(const char *key, const char *val);
	Variant(const char *key, varvector *val);
	friend std::ostream &operator<<(std::ostream &stream,Variant &obj);
	virtual ~Variant();
};

#endif /* VARIANT_H_ */
