/*
 * AppSurfing.h
 *
 *  Created on: 18.04.2010
 *      Author: blacksmith
 */

#ifndef APPSURFING_H_
#define APPSURFING_H_

#define app_version "7.01"
#define TEST 1

#ifdef TEST
	#define SERVISE_HOST "test.vipip.ru"
	#define DB_DATABASE "vipip_main"
//	#define DB_HOST "vipip.ru"
//	#define DB_USER "vipip_test"
//	#define DB_PASSWORD "XAxGAjsqL4CdSnhc"

	#define DB_HOST "localhost"
	#define DB_USER "root"
//	#define DB_PASSWORD "aeQuooZu"
	#define DB_PASSWORD ""

#else
	#define SERVISE_HOST "vipip.ru"
	#define DB_DATABASE "vipip_main"
	#define DB_HOST "localhost"
	#define DB_USER "vipip_test"
	#define DB_PASSWORD "XAxGAjsqL4CdSnhc"
#endif


/*  Типы посещений хранятся в таблице surftype:
 1. surfid	 : идентификатор типа
 2. surfname : имя типа
 3. priceadv : цена рекламодателю
 4. priceuser: цена рекламовзятелю
 5. surfdesc : описание типа.

 Ссылки хранятся в таблице links:
 1. linkid
 userid
 2. deleted 	 : флаг удалённости ссылки
 (никакие данные из базы не уничтожаются!)
 3. url 		 : URL ссылки для посещения
 4. desc		 : Описание ссылки
 5. notify		 : Баланс ссылки для отправки уведомления
 6. stat		 : Периодичность отправки статистики
 7. hide		 : Скрывать ссылку от самого рекламодателя
 8. allowproxy	 : Разрешать доступ с публичных прокси
 9. timelimitid  : ID таблицы лимитирования по времени
 10. placetargetid: ID таблицы таргеттинга по месту
 11. surfid		 : Категория серфинга
 12. costtype	 : Тип оплаты (показы или сутки)
 13. maxshowuser  : Число показов одному пользователю в сутки
 14. maxshowday	 : Число показов в сутки
 15. balance 	 : Баланс ссылки в показах/сутках
 16. priceadv	 : Стоимость 1000 показов рекламодателю
 17. priceuser	 : Стоимость 1000 показов юзверю
 18. enabled 	 : Включенность показов

 Посещения фиксируются в таблице links_log:
 1. userid	   : пользователь, посетивший
 2. linkid	   : ссылка, которую посещали
 3. when	   : момент посещения (момент показа пользователю)
 4. success    : успешность посещения (ответ на вопрос; время показа прошло)
 5. paid	   : оплаченность посещения (верный ответ на вопрос; выигрыш в лотерею)
 6. ipaddr	   : IP посетителя
 7. proxyip    : IP посетителя из-за прокси (если использовалась прокси)
 8. sid 	   : Сессия в момент посещения

 Список таблиц временного таргеттинга timelimits:
 1. timelimitid   : ID таблицы
 2. userid		  : ID пользователя, создавшего таблицу (0 -- заготовки)
 3. timelimitdesc : описание таблицы

 Таблица временного таргеттинга timelimit
 1. timelimitid: ID таблицы таргеттинга
 2. hour	   : час
 3. visits	   : число посещений
 4. days	   : битмаска дней

 Список таблиц географического таргеттинга placetargets:
 1. placetargetid : ID таблицы таргеттинга
 2. userid		  : пользователь создавший таблицу

 Таблица георграфического таргеттинга (города) placetarget_ci:
 1. placetargetid : ID таблицы таргеттинга
 2. target		  : выделенный город

 Таблица георграфического таргеттинга (страны) placetarget_co:
 1. placetargetid : ID таблицы таргеттинга
 2. target		  : выделенная страна

 Так же постоянно считаются статистики в таблицах
 1. visitcacheuser (linkid, userid, day, visits)
 2. visitcacheday  (linkid, day, visits, visits_uniq)
 3. visitcachehour (linkid, day, hour, visits)
 4. visitcachetype (surfid, day, visits, linkid)
 5. visitcacheip   (linkid, ip, day, visits)
 6. visitgeostat   (day, cityid, visits, visits_uniq)
 7. visitstats	   (day, visits, visits_uniq)
 По крону раз в час производится:
 1. Если произошел переход через границу суток --
 удаление данных из cacheuser  старее 2х суток
 удаление данных из cacheip	  старее 2х суток
 удаление данных из cacheday   старее 2х недель
 удаление данных из cachetype  старее 2х недель
 удаление данных из visitstats старее 2х месяцев
 2. Если произошел переход через границу часа --
 удаление из cachehour старее 12 часов.
 visitcachehour содержит так же поле дня, ибо в случае сдыхания крона
 иначе будет копиться ошибка.
 */

/*
 Типы регистраций хранятся в таблице tasktype:
 1. taskid	 : идентификатор типа
 2. taskname : имя типа
 3. priceadv : цена рекламодателю
 4. priceuser: цена рекламовзятелю
 5. taskdesc : описание типа.

 Регистрации хранятся в таблице tasks:
 1. linkid
 userid
 2. deleted 	 : флаг удалённости ссылки
 (никакие данные из базы не уничтожаются!)
 3. url 		 : URL ссылки для посещения
 4. desc		 : Описание ссылки
 5. notify		 : Баланс ссылки для отправки уведомления
 6. stat		 : Периодичность отправки статистики
 7. hide		 : Скрывать ссылку от самого рекламодателя
 8. allowproxy	 : Разрешать доступ с публичных прокси
 9. timelimitid  : ID таблицы лимитирования по времени
 10. placetargetid: ID таблицы таргеттинга по месту
 11. surfid		 : Категория серфинга
 12. costtype	 : Тип оплаты (показы или сутки)
 13. maxshowuser  : Число показов одному пользователю в сутки
 14. maxshowday	 : Число показов в сутки
 15. balance 	 : Баланс ссылки в показах/сутках
 16. priceadv	 : Стоимость 1000 показов рекламодателю
 17. priceuser	 : Стоимость 1000 показов юзверю
 18. enabled 	 : Включенность показов

 Регистрации фиксируются в таблице tasks_log:
 1. userid	   : пользователь, посетивший
 2. linkid	   : ссылка, которую посещали
 3. when	   : момент посещения (момент показа пользователю)
 4. success    : успешность посещения (ответ на вопрос; время показа прошло)
 5. paid	   : оплаченность посещения (верный ответ на вопрос; выигрыш в лотерею)
 6. ipaddr	   : IP посетителя
 7. proxyip    : IP посетителя из-за прокси (если использовалась прокси)
 8. sid 	   : Сессия в момент посещения

 Список таблиц временного таргеттинга timelimits:
 1. timelimitid   : ID таблицы
 2. userid		  : ID пользователя, создавшего таблицу (0 -- заготовки)
 3. timelimitdesc : описание таблицы

 Таблица временного таргеттинга timelimit
 1. timelimitid: ID таблицы таргеттинга
 2. hour	   : час
 3. visits	   : число посещений
 4. days	   : битмаска дней

 Список таблиц географического таргеттинга placetargets:
 1. placetargetid : ID таблицы таргеттинга
 2. userid		  : пользователь создавший таблицу

 Таблица георграфического таргеттинга (города) placetarget_ci:
 1. placetargetid : ID таблицы таргеттинга
 2. target		  : выделенный город

 Таблица георграфического таргеттинга (страны) placetarget_co:
 1. placetargetid : ID таблицы таргеттинга
 2. target		  : выделенная страна

 Так же постоянно считаются статистики в таблицах
 1. taskcacheuser (linkid, userid, day, visits)
 2. taskcacheday  (linkid, day, visits, visits_uniq)
 3. taskcachehour (linkid, day, hour, visits)
 4. taskcachetype (surfid, day, visits)
 5. taskcacheip   (linkid, ip, day, visits)
 6. taskgeostats  (day, visits, visits_uniq)
 По крону раз в час производится:
 1. Если произошел переход через границу суток --
 удаление данных из cacheuser  старее 2х суток
 удаление данных из cacheip	  старее 2х суток
 удаление данных из cacheday   старее 2х недель
 удаление данных из cachetype  старее 2х недель
 удаление данных из visitstats старее 2х месяцев
 2. Если произошел переход через границу часа --
 удаление из cachehour старее 12 часов.
 visitcachehour содержит так же поле дня, ибо в случае сдыхания крона
 иначе будет копиться ошибка.
 */
/*
 Предоставляемые функции:
 1. Чистка кеша
 ClearRegisterCache();
 2. Отсылка уведомлений работодателям
 SendRegistersNotify();
 3. Изменение баланса суточных регистраций
 EatDailyLinksRests();
 4. Рассчет коэффициента стоимости для суточных регистраций
 GetDailyCostCoefficientReg();
 */

//#include "Session.h"
#include "User.h"
#include "Url.h"
#include "Response.h"

#define VIPIP_EARN 0.15;
class AppSurfing
{
public:
	User user;
	int trackip;
	char * wmid;
	char * wmr;
	char * wmz;
	char * login;
	char * session_id;
	//
	char * coderandom;
	int image_id;
	int codex;
	int codey;
	int codew;
	int codeh;
	int wronganswer;
	int autowronganswer;
	int rnd[5];
	int rightnum;
	//
	bool givestock;
	mysqlpp::Connection *con;
	urlvector * AppURLs;
	urlvector * AutoURLs;
	urlvector * AutoAppURLs;
	urlvector * TaskURLs;
	bool debug;
	bool testurl;
	int taskid;
	int linkid;
	int autolinkid;
	int question_right;
	char *tasklottery[3];
	char *surflottery[3];
	struct tm * timeinfo;
	time_t now;
	std::string uid;
	double beginday;
	double beginhour;
	double discount;
	double getadvref;
	double getvipip;
	AppSurfing();
	virtual ~AppSurfing();
	void Init(const char * remote_addr, const char * callFrom );
	char * Handle(const struct evkeyvalq *headers,
			const struct evkeyvalq *coockies, const char * remote_addr);
	char * Auto(const struct evkeyvalq *headers,
			const struct evkeyvalq *coockies, const char * remote_addr);
	char * TaskHandle(const struct evkeyvalq *headers,
			const struct evkeyvalq *coockies, const char * remote_addr);
	char * Login(const struct evkeyvalq *headers,
				const struct evkeyvalq *coockies, const char * remote_addr);
	bool GiveStock();
	char * ImageX(const char * image_x, const char * image_y,
			const char * lottery, const char * checkword);
	void Block(const char * block);
	std::string Check(const char * check);
	char* TransferStocks(int fromuser, int touser, int amount);
	void LoadStocksInfo();
	int ShowURL(Url * url);
	bool ShowTaskURL(Url * url);
	Url* GetURL(urlvector * URLs, bool isTask = false);
	bool UrlViewed(Url * url, int succ, int paid = 1, int app = 0, int autoapp =
			0);
	bool UrlTaskViewed(Url * url, int succ, int paid = 1, int app = 0);
	void AfterUserEarn(int userid, int surfid, int costtype, double priceuser, double priceadv,
			int paid, double getref, int category, int partnerid);
	void LocateUser();
	mysqlpp::Row GetListURLs(int autosurf = 0);
	/*mysqlpp::Row*/ bool CheckURL(Url * url);
	mysqlpp::Row GetTaskListURLs();
	/*mysqlpp::Row*/ bool CheckTaskURL(Url * url);
	void UpdateCache(int url_linkid, int user_id, int surf_id,
			char * user_location, char * today, char * tohour, char * remote_addr);
	void ServiceEarn(double amount, int earnop, int balop);
	bool ChangeBalance(int op, double amount, int userid, bool force);
	double AdvertPay(int userid, double sum, int category, int partnerid);
	double UserEarn(int userid, double sum, int vfor, int category, int partnerid);
	void PartnerEarn(int category, int partnerid, double sum);
};

#endif /* APPSURFING_H_ */
