/*
 * Url.h
 *
 *  Created on: 26.04.2010
 *      Author: blacksmith
 */

#ifndef URL_H_
#define URL_H_

#include <vector>     // для std::vector<>
#include <queue>     // для std::vector<>
#include <mysql++.h>

#define SAFE_DELETE(p) 			{if((p) != NULL) { delete	(p); (p)=NULL;}}
#define SAFE_DELETE_ARRAY(p)	{if((p) != NULL) { delete[]	(p); (p)=NULL;}}
#define SAFE_FREE(p) 			{if((p) != NULL) { free	(p); (p)=NULL;}}

class Question
{
public:
	char * question;
	char * url;
	char * comment;
	char * variants;
	Question():question(NULL), url(NULL), comment(NULL), variants(NULL){}
	~Question()
	{
		if (question) free(question); question = NULL;
		if (url) free(url); url = NULL;
		if (comment) free(comment); comment = NULL;
		if (variants) free(variants); variants = NULL;
	}
};
class CheckUrl
{
public:
	int linkid;				// -> STRING: 48388
	int balance;
	int time_limit;
	int maxshowday;
	int day_limit;
	int hour_limit;
	int count;				// -> STRING: 250225
	int day_visits;				// -> STRING: 250225
	int day;
	int hour;
	int uniq;

	CheckUrl();
	virtual ~CheckUrl();
};

class Url
{
public:
	int linkid;				// -> STRING: 48388
	int userid;				// -> STRING: 250225
	int costtype;			// -> STRING: 2
	char * url;				// -> STRING: http://gold-wm.ru/?ref=570
	float priceuser;		// -> STRING: 2.5
	float priceadv;			// -> STRING: 0
	char * surfname;		// -> STRING: VIP ������
	char * md5block;		// -> STRING: f8a27bcd2d6f150ae0dded4db4c50f30
	int surfid;				// -> STRING: 1
	int advsidecheck;		// -> STRING: 0
	int enabled;			// -> STRING: 1
	int tasktype;
	int taskid;
	int balance;
	int gettime;
	int timer;
	int code;
	int category;
	int partnerid;
	Question * question;
	/*bool deleted;			// -> STRING: 0
	char * desc;			// -> STRING: monro
	char * notify;			// -> STRING: 0
	char * stat;			// -> STRING: 0
	char * hide;			// -> STRING: 0
	char * allowproxy;		// -> STRING: 1
	char * timelimitid;		// -> STRING: 0
	char * placetargetid;	// -> STRING: 0

	char * maxshowuser;		// -> STRING: 1
	char * maxshowday;		// -> STRING: 0
	char * balance;			// -> STRING: 84

	char * notifysent;		// -> STRING: 0
	char * statsent;		// -> STRING: 2010-04-08
	char * lastcharge;		// -> STRING: 2010-04-25 09:40:09
	char * textblock;		// -> STRING: ������� ������, ������� � ������� �������,gold-wm
	char * dateblock;		// -> STRING: 2010-04-25 10:40:43
	char * hasreferer;		// -> STRING: 0
	char * manualoff;		// -> STRING: 0
	char * pornosite;		// -> STRING: 0*/
	int hasreferer;			// -> STRING: 0
	int cntinputpoint;		// -> STRING: 0
	int reginterval;		// -> STRING: 1
	int show;				// -> INT: 0
	int logid;				// -> INT: 0
	char * referer;			// -> STRING:
	Url();
	bool populate(mysqlpp::Row row);
	virtual ~Url();
};

// Опредеоение контейнера с урлами
typedef std::vector< Url* > urlvector;
typedef std::vector< Url* >::iterator uiter;

typedef std::vector< CheckUrl* > checkvector;
typedef std::vector< CheckUrl* >::iterator checkiter;

#endif /* URL_H_ */
