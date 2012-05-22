/*
 * Url.cpp
 *
 *  Created on: 26.04.2010
 *      Author: blacksmith
 */

#include "Url.h"
#include <iostream>

CheckUrl::CheckUrl() :
	linkid(0), balance(0), time_limit(0), maxshowday(0), day_limit(0), hour_limit(0), count(0), day_visits(0),  day(0), hour(0), uniq(0)
{
	// TODO Auto-generated constructor stub
}

CheckUrl::~CheckUrl()
{
	// TODO Auto-generated destructor stub
}


Url::Url() :
	linkid(0), userid(0), costtype(0), url(NULL), priceuser(0), surfname(NULL),
			md5block(NULL), enabled(0), tasktype(0), taskid(0), balance(0), gettime(0), timer(0), code(0),
			category(0), partnerid(0), question(NULL), hasreferer(0), cntinputpoint(0), reginterval(0),
			show(0), logid(0), referer(NULL)
{
	// TODO Auto-generated constructor stub
}

Url::~Url()
{
	// TODO Auto-generated destructor stub
	SAFE_FREE(url);
	SAFE_FREE(surfname);
	SAFE_FREE(md5block);
	SAFE_FREE(referer);
	SAFE_DELETE(question);
}

bool isFieldExist(const mysqlpp::FieldNames * list, const char * field)
{
	for (size_t i = 0; i < list->size(); i++)
		if (strcmp(list->at(i).c_str(), field) == 0)
			return true;
	return false;
}
bool Url::populate(mysqlpp::Row row)
{
	if (!row.empty())
	{
		const mysqlpp::FieldNames *list = row.field_list().list;
		// TODO Auto-generated constructor stub
		if (row["linkid"])
			linkid = atoi(row["linkid"].c_str());
		else
			linkid = 0;
		if (row["userid"])
			userid = atoi(row["userid"].c_str());
		else
			userid = 0;
		if (row["costtype"])
			costtype = atoi(row["costtype"].c_str());
		else
			costtype = 0;

		SAFE_FREE(url);
		url = strdup(row["url"].c_str());
		priceuser = atof(row["priceuser"].c_str());
		priceadv = atof(row["priceadv"].c_str());

		SAFE_FREE(surfname);
		if (isFieldExist(list, "surfname")) // сомнительно
			surfname = strdup(row["surfname"].c_str());

		SAFE_FREE(md5block);
		if (isFieldExist(list, "md5block")) // сомнительно
			md5block = strdup(row["md5block"].c_str());

		if (isFieldExist(list, "surfid"))
			surfid = atoi(row["surfid"].c_str());
		else
			surfid = 0;

		if (isFieldExist(list, "advsidecheck"))
			advsidecheck = atoi(row["advsidecheck"].c_str());
		else
			advsidecheck = 0;

		if (isFieldExist(list, "enabled"))
			enabled = atoi(row["enabled"].c_str());
		else
			enabled = 0;

		if (isFieldExist(list, "tasktype"))
			tasktype = atoi(row["tasktype"].c_str());
		else
			tasktype = 0;

		if (isFieldExist(list, "taskid"))
			taskid = atoi(row["taskid"].c_str());
		else
			taskid = 0;

		if (isFieldExist(list, "hasreferer"))
			hasreferer = atoi(row["hasreferer"].c_str());
		else
			hasreferer = 0;

		if (isFieldExist(list, "cntinputpoint"))
			cntinputpoint = atoi(row["cntinputpoint"].c_str());
		else
			cntinputpoint = 0;

		if (isFieldExist(list, "reginterval"))
			reginterval = atoi(row["reginterval"].c_str());
		else
			reginterval = 0;

		if (isFieldExist(list, "balance"))
			balance = atoi(row["balance"].c_str());
		else
			balance = 0;
		if (isFieldExist(list, "timer"))
			timer = atoi(row["timer"].c_str());
		else
			timer = 30;
		if (isFieldExist(list, "code"))
			code = atoi(row["code"].c_str());
		else
			code = 0;
		if (isFieldExist(list, "usercategory"))
			category = atoi(row["usercategory"].c_str());
		else
			category = 0;
		if (isFieldExist(list, "partnerid"))
			partnerid = atoi(row["partnerid"].c_str());
		else
			partnerid = 0;
		return true;
	}
	return false;
	/*
	 deleted;			// -> STRING: 0
	 desc;			// -> STRING: monro
	 notify;			// -> STRING: 0
	 stat;			// -> STRING: 0
	 hide;			// -> STRING: 0
	 allowproxy;		// -> STRING: 1
	 timelimitid;		// -> STRING: 0
	 placetargetid;	// -> STRING: 0
	 surfid;				// -> STRING: 1
	 costtype;			// -> STRING: 2
	 maxshowuser;		// -> STRING: 1
	 maxshowday;		// -> STRING: 0
	 balance;			// -> STRING: 84
	 notifysent;		// -> STRING: 0
	 statsent;		// -> STRING: 2010-04-08
	 lastcharge;		// -> STRING: 2010-04-25 09:40:09
	 advsidecheck;	// -> STRING: 0
	 reginterval;		// -> STRING: 1
	 textblock;		// -> STRING: ������� ������, ������� � ������� �������,gold-wm
	 dateblock;		// -> STRING: 2010-04-25 10:40:43
	 hasreferer;		// -> STRING: 0
	 manualoff;		// -> STRING: 0
	 pornosite;		// -> STRING: 0
	 show;				// -> INT: 0
	 logid;				// -> INT: 0
	 referer;			// -> STRING:*/
}
