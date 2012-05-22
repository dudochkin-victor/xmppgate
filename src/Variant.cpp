/*
 * Variant.cpp
 *
 *  Created on: 26.04.2010
 *      Author: blacksmith
 */

#include "Variant.h"
using namespace std;
#include <algorithm>  // для std::for_each()
#include <sstream>

Variant::Variant(): value (NULL)
{
	this->type = T_NULL;
	this->value = (void *)"NULL";
}

Variant::Variant(const char *key): value (NULL)
{
	this->type = T_NULL;
	this->key = strdup(key);
	this->value = NULL;
}

Variant::Variant(const char *key, int val)
{
	this->type = T_INT;
	this->key = strdup(key);
	value = malloc(sizeof(int));
	(*(int*)this->value) = val;
}

Variant::Variant(const char *key, const char *val)
{
	type = T_STRING;
	this->key = strdup(key);
	if (val != NULL) this->value = strdup(val);
}

Variant::Variant(const char *key, varvector *val)
{
	type = T_ARRAY;
	this->key = strdup(key);
	if (val != NULL) this->value = (void *)val;
}

// деструктор
Variant::~Variant()
{
	if (key) free(key);
	if (value)
	{
		if (type== T_ARRAY)
		{
			// Переберём все объекты в контейнере
			varvector *items= (varvector*)value;
			for (viter element = items->begin(); element < items->end(); element++)
				delete (*element);
			items->clear();
			delete (varvector*)value;
		} else if ((type== T_STRING) || (type == T_INT))
		{
			free(value);
		}
	}
}

ostream &operator<<(ostream &stream,Variant &obj) {
	switch (obj.type)
	{
	case T_NULL:
		stream << "s:" << strlen(obj.key) << ":\"" << obj.key << "\";N;";
		break;
	case T_INT:
		stream << "s:" << strlen(obj.key) << ":\"" << obj.key
			<< "\";i:" << *((int*)obj.value) << ";";
		break;
	case T_STRING:
		stream << "s:" << strlen(obj.key) << ":\"" << obj.key <<
			"\";s:" << strlen((char*)obj.value) << ":\"" << (char*)obj.value << "\";";
		break;
	case T_ARRAY:
		// Переберём все объекты в контейнере
		varvector *items= (varvector*)obj.value;
		stream << "s:" << strlen(obj.key) << ":\"" << obj.key <<
				"\";a:" << items->size()<< ":{";
		for (viter element = items->begin(); element < items->end(); element++)
		{
			Variant *t = (*element);
			stream << *t;
		}
		stream <<"}";
		break;
	}
	return stream;
}
