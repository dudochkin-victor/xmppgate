/*
 * AppSurfing.cpp
 *
 *  Created on: 18.04.2010
 *      Author: blacksmith
 */

#include "AppSurfing.h"

using namespace std;

//TODO: $GLOBALS['LoadStocksInfo'])
bool GLoadStocksInfo = false;

extern checkvector * CheckURLs;
extern checkvector * CheckTaskURLs;

AppSurfing::AppSurfing() :
	trackip(0), wmid(NULL), wmr(NULL), wmz(NULL), login(NULL),
			session_id(NULL), coderandom(0), image_id(0), codex(0), codey(0),
			codew(0), wronganswer(0), autowronganswer(0), con(NULL), taskid(0),
			linkid(0), autolinkid(0), question_right(0)
{
	// TODO Auto-generated constructor stub
	givestock = false;
	AppURLs = new urlvector;
	AutoURLs = new urlvector;
	AutoAppURLs = new urlvector;
	TaskURLs = new urlvector;
	debug = true;
	testurl = false;
	rnd[0] = 0;
	rnd[1] = 0;
	rnd[2] = 0;
	rnd[3] = 0;
	rnd[4] = 0;
	surflottery[0] = NULL;
	surflottery[1] = NULL;
	surflottery[2] = NULL;
	tasklottery[0] = NULL;
	tasklottery[1] = NULL;
	tasklottery[2] = NULL;
}
Url * url_find(urlvector *items, int id)
{
	for (uiter element = items->begin(); element < items->end(); element++)
	{
		Url *t = (*element);
		if ((t) && (t->linkid == id))
			return t;
	}
	return NULL;
}

CheckUrl * check_find(checkvector *items, int id)
{
	for (checkiter element = items->begin(); element < items->end(); element++)
	{
		CheckUrl *t = (*element);
		if ((t) && (t->linkid == id))
			return t;
	}
	return NULL;
}

void urls_show(urlvector *items, int id)
{
	for (uiter element = items->begin(); element < items->end(); element++)
	{
		Url *t = (*element);
		DEBUG("%d URL %d %s %d %d %s", id, t->linkid, t->url, t->show, t->gettime, t->surfname);

	}
}

AppSurfing::~AppSurfing()
{
	Url *t = NULL;
	for (uiter element = AppURLs->begin(); element < AppURLs->end(); element++)
	{
		t = (*element);
		SAFE_DELETE(t);
	}

	AppURLs->clear();
	SAFE_DELETE(AppURLs);
	AppURLs = NULL;

	for (uiter element = AutoURLs->begin(); element < AutoURLs->end(); element++)
	{
		t = (*element);
		SAFE_DELETE(t);
	}
	AutoURLs->clear();
	SAFE_DELETE(AutoURLs);
	AutoURLs = NULL;

	for (uiter element = AutoAppURLs->begin(); element < AutoAppURLs->end(); element++)
	{
		t = (*element);
		SAFE_DELETE(t);
	}
	AutoAppURLs->clear();
	SAFE_DELETE(AutoAppURLs);
	AutoAppURLs = NULL;

	for (uiter element = TaskURLs->begin(); element < TaskURLs->end(); element++)
	{
		t = (*element);
		SAFE_DELETE(t);
	}
	TaskURLs->clear();
	SAFE_DELETE(TaskURLs);
	TaskURLs = NULL;

	// TODO Auto-generated destructor stub
	SAFE_FREE(wmid);
	SAFE_FREE(wmz);
	SAFE_FREE(wmr);
	SAFE_FREE(login);
	SAFE_FREE(session_id);
	SAFE_FREE(surflottery[0]);
	SAFE_FREE(surflottery[1]);
	SAFE_FREE(surflottery[2]);
	SAFE_FREE(tasklottery[0]);
	SAFE_FREE(tasklottery[1]);
	SAFE_FREE(tasklottery[2]);

	if (con)
		con = NULL;
}

// Возможно, стоит конфиг вынести из бд в memcache ? Хотя врядли много времени требует
void AppSurfing::LoadStocksInfo()
{

	DEBUG("%d AppSurfing::LoadStocksInfo");
	if (GLoadStocksInfo)
	{
		GLoadStocksInfo = 1;
		mysqlpp::Query query = con->query();
		query << "SELECT name,value FROM stocks";
		mysqlpp::StoreQueryResult res = query.store();
		if (res)
		{
			mysqlpp::Row row = res.at(0);
			mysqlpp::Row::size_type i;
			for (i = 0; row = res.at(i); ++i)
			{
				//TODO: $GLOBALS['stocks'][$v['name']] = row['value'];
			}
			//			res.purge();
		}
		else
		{

			DEBUG("%d LoadStocksInfo NO RES: %s", user.userid, query.error());
		}
	}
}

char* AppSurfing::TransferStocks(int fromuser, int touser, int amount)
{

	DEBUG("%d AppSurfing::TransferStocks", user.userid);
	//$StocksSummaryInterval;
	LoadStocksInfo();
	const char
			* loghdr =
					"INSERT INTO stocks_log(stockop,`when`,userid,target,amount,rate,comission) VALUES ";
	// now = sql_quote(date("YmdHis", $curts));
	if (fromuser == 0)
	{ // Выдача системой
		mysqlpp::Query query = con->query();
		query << "UPDATE stocks SET value=value-" << amount
				<< " WHERE name='free_stocks' AND value>=" << amount;
		mysqlpp::SimpleResult res = query.execute();
		if (res)
		{
			if (res.rows() == 1)
			{
				query << loghdr << "(6," << now << "," << touser << ",0,"
						<< amount << ","
						<< "$GLOBALS['stocks']['current_price']" << ",0)";
				query.execute();
				query << "UPDATE user SET stocks=stocks+" << amount
						<< " WHERE userid=" << touser;
				query.execute();
				return (char*) "Вам выдано акций: ";// amount;
			}
			else
			{
				query << "UPDATE stocks SET value=value+" << amount
						<< " WHERE name='free_stocks'";
				query.execute();
				return (char*) "У системы недостаточно акций";
			}
		}
		else
		{

			DEBUG("%d TransferStocks1 NO RES: %s", user.userid, query.error());
		}
		return NULL;
	}
	else
	{ // Перевод между пользователями
		char *ret = NULL;
		if (fromuser != user.userid)
			return (char*) "Попытка перевода от лица чужого пользователя";

		/*if (amount < $GLOBALS['stocks']['min_transfer']) {
		 return "Минимальный объем акций для перевода: ".$GLOBALS['stocks']['min_transfer'];
		 }*/
		int comission = 0;// = intval(amount * $GLOBALS['stocks']['transfer_com']);
		if (comission < 1)
			comission = 1;
		// Пытаемся изъять акции у юзера...
		mysqlpp::Query query = con->query();
		query << "UPDATE user SET stocks = stocks-" << (amount + comission)
				<< " WHERE userid=" << fromuser << " AND stocks>=" << (amount
				+ comission);
		mysqlpp::StoreQueryResult res = query.store();
		if (res)
		{
			if (res.num_rows() == 1)
			{
				// Если у него хватило, то всё ок -- начисляем освободившиеся
				query << loghdr << "(3," << now << "," << fromuser << ","
						<< touser << ",-" << amount << ","
						<< "$GLOBALS['stocks']['current_price']" << ","
						<< comission << "), " << "(4," << now << ","
						<< fromuser << ",0,-" << comission << ","
						<< "$GLOBALS['stocks']['current_price']" << ",0), "
						<< "(5," << now << "," << touser << "," << fromuser
						<< "," << amount << ","
						<< "$GLOBALS['stocks']['current_price']" << ",0)";
				query.execute();
				//mysqlpp::Query query = con->query();
				query << "UPDATE stocks SET value=value+" << comission
						<< " WHERE name='free_stocks'";
				query.execute();
				query << "UPDATE user SET stocks=stocks+" << amount
						<< " WHERE userid=" << touser;
				query.execute();
				ret = (char*) "Перевод совершен успешно";
			}
			else
			{
				ret
						= (char*) "У вас недостаточно акций для перевода и комиссии (надо "
						/*($amount+$comission).*/" шт)";
			}
		}
		else
		{

			DEBUG("%d TransferStocks2 NO RES: %s", user.userid, query.error());
		}
		return ret;
	}
}

#include <crypto++/cryptlib.h>
#include <crypto++/md5.h>
#include <crypto++/hex.h>

char* utf8_to_cp1251(const char *source);

bool linkscmp(Url *a, Url* b)
{
	if (a->show != b->show)
		return (a->show > b->show);
	if (a->gettime != b->gettime)
		return (a->gettime < b->gettime);

	if (a->code != b->code)
		return (a->code < b->code);
	else
		return (a->balance < b->balance);
}

bool taskscmp(Url *a, Url* b)
{
	if (a->code != b->code)
		return (a->code < b->code);
	else
		return (a->code < b->code);
}

char * AppSurfing::Login(const struct evkeyvalq *headers,
		const struct evkeyvalq *coockies, const char * remote_addr)
{
	const char * logn = evhttp_find_header(headers, "logn");
	const char * pass = evhttp_find_header(headers, "pass");

	if (logn && (strlen(logn) > 0) && pass && (strlen(pass) > 0))
	{
		CryptoPP::MD5 hash;
		byte digest[CryptoPP::MD5::DIGESTSIZE];
		//char * _pass = utf8_to_cp1251(pass);
		// Генерируем md5 пароля
		hash.CalculateDigest(digest, (byte*) /*_*/pass, strlen(/*_*/pass));
		CryptoPP::HexEncoder encoder;
		std::string output;
		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();
		//SAFE_FREE(_pass);

		mysqlpp::StoreQueryResult res;
		// Устанавливаем время чтобы не собраться в мусор
		now = time(NULL);
		timeinfo = localtime(&now);
		now += timeinfo->tm_gmtoff;

		mysqlpp::Query query = con->query();
		query
				<< "SELECT auth.*, user.*,userref.refuperc as refrefuperc,authref.login as reflogin "
				<< "FROM auth NATURAL JOIN user "
				<< "LEFT JOIN user AS userref ON (userref.userid=auth.refid) "
				<< "LEFT JOIN auth AS authref ON (authref.userid=auth.refid) "
				<< "WHERE auth.login=" << mysqlpp::quote << logn << " AND "
				<< "(auth.passmd5 = " << mysqlpp::quote << output.c_str()
				<< ")";

		DEBUG("LOGIN: %s", query.str().c_str());
		try
		{
			res = query.store();
			if (res.num_rows() == 1)
			{
				mysqlpp::Row row = res.at(0);
				int cat = atoi(row["category"].c_str());
				if (cat < 0)
					return strdup((char*) "<vipip>\n"
						"<message>AccountBlocked</message>\n"
						"<cmd>login</cmd>\n"
						"</vipip>\n");
				if (cat == 0)
					return strdup((char*) "<vipip>\n"
						"<message>AccountNotActivated</message>\n"
						"<cmd>login</cmd>\n"
						"</vipip>\n");

				DEBUG("%d Login %d", user.userid, res.num_rows());

				std::string keybuf = remote_addr;
				keybuf.append(app_version);
				char buffer[33];
				sprintf(buffer, "%d", rand());
				keybuf.append(buffer);
				keybuf.append(logn);
				hash.CalculateDigest(digest, (byte*) keybuf.c_str(),
						keybuf.length());

				CryptoPP::HexEncoder encoder;
				std::string output;
				encoder.Attach(new CryptoPP::StringSink(output));
				encoder.Put(digest, sizeof(digest));
				encoder.MessageEnd();
				std::transform(output.begin(), output.end(), output.begin(),
						::tolower);
				if (!session_id)
					session_id = strdup(output.c_str());

				user.balance = atof(row["balance"].c_str());
				user.userid = atoi(row["userid"].c_str());
				user.advside = atoi(row["advside"].c_str());
				user.pornosite = atoi(row["pornosite"].c_str());
				user.showcat = atoi(row["showcat"].c_str());
				user.moder = atoi(row["moder"].c_str());
				SAFE_FREE(user.remote_addr);
				user.remote_addr = strdup(remote_addr);
				// заполняем uid
				uid.clear();
				uid.append(logn);
				uid.append(remote_addr);
				SAFE_FREE(login);
				login = strdup(logn);
				SAFE_FREE(wmid);
				wmid = strdup(row["wmid"].c_str());
				SAFE_FREE(wmz);
				wmz = strdup(row["wmz"].c_str());
				SAFE_FREE(wmr);
				wmr = strdup(row["wmr"].c_str());
				query << "UPDATE auth SET sid=" << mysqlpp::quote << session_id
						<< ", lastlogin=NULL WHERE login=" << mysqlpp::quote
						<< logn;
				query.execute();
				return strdup((char*) "OK");
			}
		} catch (const mysqlpp::BadQuery& er)
		{
			// Handle any query errors
			DEBUG("ACHTUNG Query error: %s", er.what());
		} catch (const mysqlpp::BadConversion& er)
		{
			// Handle bad conversions
			DEBUG("ACHTUNG Conversion error: %s \tretrieved data size: %d , actual size: %d", er.what(),
					er.retrieved, er.actual_size);
		} catch (const mysqlpp::Exception& er)
		{
			// Catch-all for any other MySQL++ exceptions
			DEBUG(" ACHTUNG Error: %s", er.what());
		}
	}
	return strdup((char*) "<vipip>\n"
		"<message>AuthError</message>\n"
		"<cmd>login</cmd>\n"
		"</vipip>\n");
}

string AppSurfing::Check(const char * check)
{

	DEBUG("%d AppSurfing::Check", user.userid);
	givestock = GiveStock();

	// выдача акции
	string mess = "Произошла ошибка при выдаче акции";
	if (givestock)
	{
		if (strcmp(coderandom, check) == 0)
		{
			mess = TransferStocks(0, user.userid, 1);
		}
		else
		{
			mess = "Вы ввели не верный код\n";
		}
	}

	return "<vipip><message>" + mess + "</message></vipip>";
	//die;
}

void AppSurfing::Block(const char * block)
{

	DEBUG("%d AppSurfing::Block ", user.userid);

	if (block)
	{
		Url *url = NULL;
		if (AppURLs->size() > 0)
		{
			url = AppURLs->at(0);
			// TODO: Разобраться чтоза 0 присоединяется.

			DEBUG("%d AppSurfing::Block %s ", user.userid, block);
			mysqlpp::Query query = con->query();
			try
			{
				query << "REPLACE INTO links_block VALUES (" << url->linkid
						<< "," << user.userid << "," << mysqlpp::quote << block
						<< ")";
				query.execute();
			} catch (const mysqlpp::BadQuery& er)
			{
				// Handle any query errors
				DEBUG("%d ACHTUNG Query error: %s", user.userid, er.what());
			} catch (const mysqlpp::BadConversion& er)
			{
				// Handle bad conversions
				DEBUG("%d ACHTUNG Conversion error: %s \tretrieved data size: %d , actual size: %d", user.userid, er.what(),
						er.retrieved, er.actual_size);
			} catch (const mysqlpp::Exception& er)
			{
				// Catch-all for any other MySQL++ exceptions
				DEBUG("%d ACHTUNG Error: %s", user.userid, er.what());
			}
		}
		else
		{

			DEBUG("%d ACHTUNG Error: no links when block", user.userid);
		}
	}
	else
	{

		DEBUG("%d no block", user.userid);
	}
	linkid = 0;
}

bool AppSurfing::GiveStock()
{
	int givestock;

	DEBUG("%d AppSurfing::GiveStock", user.userid);
	// Выдвавать ли акцию
	GetListURLs();
	int leftcnt = AppURLs->size();
	givestock = 0;
	if (leftcnt == 0 && user.showcat == -1 && //включен просмотр всех ссылок
			user.advside == 1) //включен просмотр ссылок без фрейма
	{
		mysqlpp::StoreQueryResult res;
		// Проверим, что человек сегодня что-либо смотрел, и еще не получал акций
		mysqlpp::Query query = con->query();
		query
				<< "SELECT SUM(visits) as s FROM visitcacheuser WHERE day=CURRENT_DATE and userid="
				<< user.userid;
		res = query.store();
		int vs;
		if (res)
		{
			mysqlpp::Row row = res.at(0);
			if (row)
				vs = row['s'];
			//			res.purge();
		}
		else
		{

			DEBUG("%d GiveStock1 NO RES: %s", user.userid, query.error());
		}

		query << "SELECT logid FROM stocks_log " << "WHERE stockop=6 AND "
				<< "`when`>=CURRENT_DATE AND " << "userid=" << user.userid;
		res = query.store();
		if (res)
		{
			givestock = ((res.num_rows() == 0) && (vs > 0));
			//			res.purge();
		}
		else
		{

			DEBUG("%d GiveStock2 NO RES: %s", user.userid, query.error());
		}
	}
	return givestock;
}

char * AppSurfing::ImageX(const char * image_x, const char * image_y,
		const char * lottery, const char * checkword)
{

	DEBUG("%d ImageX: %s %s %s %s", user.userid, image_x, (image_y ? image_y : ""), (lottery ? lottery : ""),
			(checkword ? checkword : ""));
	char *mess;
	double paid = 0;
	int dbl = 0;
	int wordcheck = 0;
	int lott = 1;
	char * res = NULL;

	// Правильно ли угадали цифру
	if (codew)
	{
		int ix = atoi(image_x);

		DEBUG("%d HAVE ALL NUMBERS %d %d %d", user.userid, ix, codex, codew);
		paid = ((ix > codex) && (ix < codew)) ? 1 : 0;
	}

	dbl = (user.doublepaytime > now) ? 2 : 1;
	if (surflottery[0])
		lott = (lottery) ? ((strcmp(lottery, surflottery[rand() % 3]) == 0) ? 2
				: 0) : 1;

	// Просмотр ссылки по серфингу
	Url *url = NULL;
	if (AppURLs->size() > 0)
		url = AppURLs->at(0);
	else
	{

		DEBUG("%d !!! НЕТУ УРЛА", user.userid);
		return NULL;
	}
	if (checkword)
	{
		wordcheck = ((url->md5block == NULL) || (strcmp(checkword,
				url->md5block)) == 0
		// Если еще нет данных по заголовку
				/*||  strcmp(url->md5block, "") == 0*/) ? 1 : 0;
	}
	wordcheck = 1; //DV


	DEBUG("%d IMAGEX checkword: [%s] md5block: [%s]", user.userid, checkword, url->md5block);
	// TODO: Сделать добавление в сессию
	//	if (wordcheck)
	//		wronganswer = 0;
	//	else
	//		wronganswer++;
	//
	//	if (wronganswer < 3)
	//		wordcheck = 1;

	bool viewed = UrlViewed(url, paid * wordcheck, lott * wordcheck * dbl, 1);
	//DEBUG("%d paid %f wordcheck %d lott %d", user.userid, paid, wordcheck, lott);
	/* << " lottery:" << (lottery ? lottery : "|")
	 << " dbl " << dbl << " viewed " << viewed << " url->priceuser "
	 << url->priceuser << endl;*/
	double earn = 0;
	if (viewed && paid && wordcheck)
	{
		earn = url->priceuser / 1000.0 * lott * dbl;
		user.balance += earn;
	}

	char buf[200];
	sprintf(buf, "Earn: %1.4f$", earn);

	if (paid > 0)
	{
		if (lott == 2)
			res = (char*) "EarnTo 2x";
		else if (lott == 1)
			res = (char*) "EarnTo";
		else
			res = (char*) "EarnTo 0x";
	}

	if (!viewed)
		mess = strdup("ErrViewPage");
	else
	{
		SAFE_DELETE(AppURLs->at(0));
		AppURLs->erase(AppURLs->begin());
		mess = strdup(buf);
	}

	linkid = 0;

	DEBUG("%d (%s) %s", user.userid, login, mess);
	return mess;
}
char * str_rand(int num, const char * val)
{
	char * buff = (char*) malloc((num + 1) * sizeof(char));
	memset(buff, '\0', (num + 1) * sizeof(char));
	int len = strlen(val);
	for (int i = 0; i < num; i++)
		buff[i] = val[rand() % len];
	return buff;
}

void AppSurfing::Init(const char * remote_addr, const char * callFrom)
{
	SAFE_FREE(user.remote_addr);
	user.remote_addr = strdup(remote_addr);
	user.remoteAddr = htonl(inet_addr(user.remote_addr));
	if (!user.user_location)
		LocateUser();

	DEBUG("%d HI IAM (%s) %s REMOTE: %s CALL: %s", user.userid, ((login) ? login : " "), session_id, user.remote_addr, callFrom );
	/*<< " CityID: " << user.user_location << " trackip:" << trackip
	 << "|" << ((wmid) ? wmid : " ") << "|"
	 << ((wmz) ? wmz : " ") << "|" << ((wmr) ? wmr : "|") << endl;*/
	now = time(NULL);
	timeinfo = localtime(&now);
	now += timeinfo->tm_gmtoff;
	beginday = (now % 86400) / 86400.0; // Минут с начала суток
	beginhour = (now % 3600) / 3600.0; // Минут с начала часа
	/*mysqlpp::Query query = con->query();
	 query << "SET character_set_client=utf8";
	 query.execute();
	 query << "SET character_set_connection=utf8";
	 query.execute();
	 query << "SET character_set_results=utf8";
	 query.execute();*/
}

char * AppSurfing::Handle(const struct evkeyvalq *headers,
		const struct evkeyvalq *coockies, const char * remote_addr)
{
	ostringstream buffer;
	char * mess = NULL;
	char * fn = NULL;
	// TODO: поменять на дабл

	Init(remote_addr, "Handle");

	DEBUG("%d AppSurfing::Handle", user.userid);

	// Получение акции
	const char * check = evhttp_find_header(headers, "check");
	if (check && (strlen(check) > 0))
		this->Check(check);

	// Блокировка страниц
	const char * block = evhttp_find_header(headers, "block");
	const char * blockchk = evhttp_find_header(headers, "blockchk");

	if (blockchk)
		this->Block(block);
	else if (block)
	{

		DEBUG("%d Blocking: %d %s", user.userid, linkid, block);
		linkid = 0;
	}

	// пропускаем
	const char * next = evhttp_find_header(headers, "next");
	if (next /*&& (strlen(next) > 0)*/)
	{
		if (AppURLs->size() > 0)
		{
			SAFE_DELETE(AppURLs->at(0));
			AppURLs->erase(AppURLs->begin());
		}
		linkid = 0;
	}

	const char * image_x = evhttp_find_header(headers, "image_x");
	const char * image_y = evhttp_find_header(headers, "image_y");
	const char * tlottery = evhttp_find_header(headers, "lottery");
	const char * checkword = evhttp_find_header(headers, "checkword");

	// Пользователь ткнул на изображение
	if (image_x && (strlen(image_x) > 0))
		mess = ImageX(image_x, image_y, tlottery, checkword);

	Url *url = NULL;
	if (!linkid)
	{

		DEBUG("%d no linkid", user.userid);

		if (AppURLs->size() == 0)
			GetListURLs();

		bool wdo = true;
		while (wdo)
		{
			// Получаем новый URL для просмотра
			url = GetURL(AppURLs);
			if (url)
			{
				if (url->show != 0)
				{

					DEBUG("%d erase url %d", user.userid, url->linkid);
					SAFE_DELETE(AppURLs->at(0));
					AppURLs->erase(AppURLs->begin());
				}
				else
					wdo = false;
			}
			else
			{
				if (AppURLs->size() > 0)
				{

					DEBUG("%d erase url becouse is not checked %d", user.userid, AppURLs->at(0)->linkid);
					SAFE_DELETE(AppURLs->at(0));
					AppURLs->erase(AppURLs->begin());
				}
				else
					wdo = false;
			}
		}

		if (url)
		{
			// TODO тоже пока не понятно нахера эта заепательская логика здесь.
			linkid = url->linkid;

			Url * turl = AppURLs->at(0);
			turl->logid = ShowURL(url);
			turl->show = now;
			{
				if (!turl->logid)
					DEBUG("%d ACHTUNG NO LOGID", user.userid);
					else
					DEBUG("%d URL %d %d %d %d", user.userid, url->linkid,
							turl->linkid, url->show, turl->show);
			}
			// Получаем referer для текущей ссылки
			SAFE_FREE(url->referer);
			if (url->hasreferer)
			{
				int rnd_ref = rand() % (url->hasreferer);
				mysqlpp::Query query = con->query();
				query << "SELECT referer FROM links_referer_mem WHERE linkid="
						<< url->linkid << " LIMIT " << rnd_ref << ",1";
				mysqlpp::StoreQueryResult res = query.store();
				if (res && (res.num_rows() > 0))
				{
					mysqlpp::Row row = res.at(0);
					url->referer = strdup(row["referer"].c_str());
					//				res.purge();
				}
				else
				{

					DEBUG("%d REFFERER NO RES: %s", user.userid, query.error());
				}
			}

			// Получаем точку входа для текущей ссылки
			if (url->cntinputpoint)
			{
				int rnd_inp = rand() % (url->cntinputpoint);
				mysqlpp::Query query = con->query();
				query << "SELECT url FROM links_inputpoint_mem WHERE linkid="
						<< url->linkid << " LIMIT " << rnd_inp << ",1";
				mysqlpp::StoreQueryResult res = query.store();
				if (res && (res.num_rows() > 0))
				{
					mysqlpp::Row row = res.at(0);
					SAFE_FREE(url->url);
					url->url = strdup(row["url"].c_str());
					//				res.purge();
				}
				else
				{

					DEBUG("%d INPUTPOINT NO RES: %s", user.userid, query.error());
				}
			}
		}

		//unset($_SESSION['poll']);
	}

	if (!url)
	{ // Просмотр завершен!

		DEBUG("%d no url", user.userid);

		//TODO сам кодепэйдж тоже надо грохнуть по идее, хотя нахера всё это делается мне пока не понятно
		SAFE_FREE(surflottery[0]);
		SAFE_FREE(surflottery[1]);
		SAFE_FREE(surflottery[2]);

		linkid = 0;

		buffer << "<vipip>\n" << "<endsurf>EndView</endsurf>\n" << "<balance>"
				<< fixed << setprecision(4) << user.balance << "</balance>"
				<< "<banner1>http://"SERVISE_HOST"/banners/app/load?type=3</banner1>"
				<< (givestock ? "<cmd>stock</cmd>" : "") << "</vipip>";
	}
	else
	{
		//TODO сам кодепэйдж тоже надо грохнуть по идее, хотя нахера всё это делается мне пока не понятно
		/*Variant *codepage = sess->find("code", "page", NULL);
		 if (codepage)
		 ((varvector*)codepage->value)->clear(); // грохнем там всё */
		SAFE_FREE(surflottery[0]);
		SAFE_FREE(surflottery[1]);
		SAFE_FREE(surflottery[2]);

		surflottery[0] = str_rand(3, "acdefghmnpqstwyz2345789");
		surflottery[1] = str_rand(3, "acdefghmnpqstwyz2345789");
		surflottery[2] = str_rand(3, "acdefghmnpqstwyz2345789");

		/*if (url && !url->advsidecheck)
		 {
		 DEBUG("%d RND NOT START", user.userid);
		 int id = rand() % 10000 + 1;
		 mysqlpp::Query query = con->query();
		 query << "SELECT * FROM `surfimage_mem` WHERE id=" << id;
		 mysqlpp::ResUse res = query.use();
		 if (!res)
		 fn = (char*) "";
		 else
		 {
		 mysqlpp::Row row;
		 while (row = res.fetch_row())
		 {
		 //$_SESSION["code"]["page"] = row;
		 fn = (char *) row["fn"].c_str();
		 }
		 }
		 }*/

		if (url /*&&url->advsidecheck*/)
		{
			int i = 0;
			while (true)
			{
				int r = rand() % 800 + 101; // Диапазон чисел 100, 900
				if ((rnd[0] != r) && (rnd[1] != r) && (rnd[2] != r) && (rnd[3]
						!= r) && (rnd[4] != r))
				{
					rnd[i] = r;
					i++;
				}
				if (i > 4)
					break;
			}
			rightnum = rnd[rand() % 5];
		}
		char controlimg[200];
		char advside[200];
		if (url->advsidecheck)
		{
			sprintf(
					controlimg,
					"http://"SERVISE_HOST":8081/user/appctrlimage/?r=%i&sid=%s",
					rand(), session_id);
			sprintf(
					advside,
					"<advside>http://"SERVISE_HOST":8081/user/appsideimage/?r=%i&sid=%s</advside>",
					rand(), session_id);
		}
		else
		{
			if (fn)
				sprintf(controlimg,
						"http://"SERVISE_HOST"/imgdyn/surfimage/%s.png", fn);
			else
				sprintf(
						controlimg,
						"http://"SERVISE_HOST":8081/user/appsurfimage/?r=%i&sid=%s",
						rand(), session_id);
			//"http://"SERVISE_HOST"/imgdyn/appcode2.php?r=%i&sid=%s", rand(), session_id);

		}

		char banner1[200];
		if (url->linkid == 14980)
			sprintf(
					banner1,
					"<banner1>http://"SERVISE_HOST"/poll?pollid=1&sid=%s</banner1>",
					session_id);
		else
			sprintf(
					banner1,
					"<banner1>http://"SERVISE_HOST"/banners/app/load?type=3</banner1>");

		/*char md5[200];
		 sprintf(
		 md5,
		 "<banner1>http://"SERVISE_HOST"/banners/app/load?type=3</banner1>");*/

		buffer << "<vipip>" << "<url>" << url->url << "</url>" << "<surftype>"
				<< url->surfname << "</surftype>" << "<referer>"
				<< (url->referer ? url->referer : "") << "</referer>"
				<< "<controlimg>" << controlimg << "</controlimg>"
				<< "<lottery>" << surflottery[0] << "|" << surflottery[1]
				<< "|" << surflottery[2] << "</lottery>" << banner1
				<< "<message>" << (mess ? mess : "") << "</message>"
				<< "<version>" << app_version << "</version>" //<< md5
				<< "<timer>" << url->timer << "</timer>" << "<balance>"
				<< fixed << setprecision(4) << user.balance << "</balance>"
				<< (url->advsidecheck ? advside : "") << "<counters>"
				<< "<item>http://counter.yadro.ru/hit?t14.6;" << rand()
				<< "</item>" << "<item>http://counter.rambler.ru/top100.cnt?"
				<< rand() << "</item>"
				<< "<item>http://d1.c4.b1.a1.top.list.ru/counter?t=56;rand="
				<< rand() << "</item></counters></vipip>";
	}

	SAFE_FREE(mess);
	char * buf = strdup(buffer.str().c_str());
	return buf;
}

char * AppSurfing::Auto(const struct evkeyvalq *headers,
		const struct evkeyvalq *coockies, const char * remote_addr)
{
	ostringstream buffer;
	Init(remote_addr, "Auto");

	int wordcheck = 0;
	const char * checkword = evhttp_find_header(headers, "checkword");
	const char * view = evhttp_find_header(headers, "view");
	char * mess = NULL;
	Url * url = NULL;
	char lbuf[200];
	// просмотр
	if (view && (strlen(view) > 0))
	{
		// Просмотр ссылки по серфингу
		if (AutoAppURLs->size() > 0)
		{
			url = AutoAppURLs->at(0);
			if (checkword)
			{
				wordcheck = ((url->md5block == NULL) || (strcmp(checkword,
						url->md5block) == 0)
				//Если еще нет данных по заголовку
						/*|| (strcmp(url->md5block, "") == 0)*/) ? 1 : 0;
			}
			wordcheck = 1; //DV

			//			if (checkword)
			//				autowronganswer = 0;
			//			else
			//				autowronganswer++;
			//
			//			if (autowronganswer < 3)
			//				wordcheck = 1;
			bool viewed = UrlViewed(url, 1, wordcheck, 1, 1);
			double earn = 0;

			if (viewed && wordcheck)
			{
				earn = url->priceuser / 1000.0;
				user.balance += earn;
			}
			if (!viewed)
				mess = (char*) "ErrViewPage";
			else
			{
				SAFE_DELETE(AutoAppURLs->at(0));
				AutoAppURLs->erase(AutoAppURLs->begin());
				sprintf(lbuf, "Earn: %1.4f$", earn);
				mess = &lbuf[0];
			}
		}
		autolinkid = 0;

	}
	else
		mess = (char*) "";

	if (!autolinkid)
	{
		if (AutoAppURLs->size() == 0)
			GetListURLs(1);

		bool wdo = true;
		while (wdo)
		{
			url = GetURL(AutoAppURLs); // Получаем новый URL для просмотра
			if (url)
			{
				if (url->show != 0)
				{

					DEBUG("%d erase auto url %d", user.userid, url->linkid);
					SAFE_DELETE(AutoAppURLs->at(0));
					AutoAppURLs->erase(AutoAppURLs->begin());
				}
				else
					wdo = false;
			}
			else
			{
				if (AutoAppURLs->size() > 0)
				{

					DEBUG("%d erase url becouse is not checked %d", user.userid, AutoAppURLs->at(0)->linkid);
					SAFE_DELETE(AutoAppURLs->at(0));
					AutoAppURLs->erase(AutoAppURLs->begin());
				}
				else
					wdo = false;
			}
		}

		if (url)
		{
			autolinkid = url->linkid;
			url->logid = ShowURL(url);
			url->show = now;

			// Получаем referer для текущей ссылки
			if (url->hasreferer)
			{
				int rnd_ref = rand() % (url->hasreferer);
				mysqlpp::Query query = con->query();
				query << "SELECT referer FROM links_referer_mem WHERE linkid="
						<< url->linkid << " LIMIT " << rnd_ref << ",1";
				mysqlpp::StoreQueryResult res = query.store();
				if (res && (res.num_rows() == 1))
				{
					mysqlpp::Row row = res.at(0);
					url->referer = strdup(row["referer"].c_str());
					//				res.purge();
				}
				else
				{

					DEBUG("%d AUTO1 NO RES: %s", user.userid, query.error());
				}
			}

			// Получаем точку входа для текущей ссылки
			if (url->cntinputpoint)
			{
				int rnd_inp = rand() % (url->cntinputpoint);
				mysqlpp::Query query = con->query();
				query << "SELECT url FROM links_inputpoint_mem WHERE linkid="
						<< url->linkid << " LIMIT " << rnd_inp << ",1";
				mysqlpp::StoreQueryResult res = query.store();
				if (res && (res.num_rows() > 0))
				{
					mysqlpp::Row row = res.at(0);
					SAFE_FREE(url->url);
					url->url = strdup(row["url"].c_str());
					//				res.purge();
				}
				else
				{

					DEBUG("%d INPUTPOINT NO RES: %s", user.userid, query.error());
				}
			}
		}
	}

	if (!url)
	{ // Просмотр завершен!
		autolinkid = 0;

		buffer << "<vipip><endsurf>EndView</endsurf>" << "<balance>" << fixed
				<< setprecision(4) << user.balance << "</balance>"
				<< "<banner1>http://"SERVISE_HOST"/banners/app/load?type=3</banner1>"
				<< "</vipip>";
	}
	else
	{
		buffer << "<vipip><url>" << url->url << "</url><surftype>"
				<< url->surfname << "</surftype><referer>"
				<< (url->referer ? url->referer : "") << "</referer>"
				<< "<banner1>http://"SERVISE_HOST"/banners/app/load?type=3</banner1>"
				<< "<message>" << mess << "</message>" << "<version>"
				<< app_version << "</version>" << "<timer>" << url->timer
				<< "</timer>" << "<balance>" << fixed << setprecision(4)
				<< user.balance << "</balance>" << "<counters>"
				<< "<item>http://counter.yadro.ru/hit?t14.6;" << rand()
				<< "</item>" << "<item>http://counter.rambler.ru/top100.cnt?"
				<< rand() << "</item>"
				<< "<item>http://d1.c4.b1.a1.top.list.ru/counter?t=56;rand="
				<< rand() << "</item>" << "</counters>"
			"</vipip>";
	}

	char * buf = strdup(buffer.str().c_str());
	return buf;
}

char * AppSurfing::TaskHandle(const struct evkeyvalq *headers,
		const struct evkeyvalq *coockies, const char * remote_addr)
{
	ostringstream buffer;
	Init(remote_addr, "TaskHandle");

	//int security = 0;
	//int surfing = 1;  // Указываем, что это серфинг. Тогда лишних проверок в login.php не будет
	char * mess = NULL;
	ostringstream variants;
	Url * url = NULL;

	// Блокировка страниц
	const char * block = evhttp_find_header(headers, "block");
	if (block && (strlen(block) > 0))
	{

		DEBUG("%d block: %s", user.userid, block);
		if (TaskURLs->size() > 0)
			url = TaskURLs->at(0);
		if (url)
		{
			mysqlpp::Query query = con->query();
			const char * blockchk = evhttp_find_header(headers, "blockchk");
			try
			{
				if (blockchk && (strlen(blockchk) > 0))
					query << "REPLACE INTO tasks_block VALUES ("
							<< (url->linkid + 0) << "," << user.userid << ","
							<< mysqlpp::quote << block << ")";
				else
				{
					query << "REPLACE INTO tasks_mess VALUES (" << (url->linkid
							+ 0) << "," << mysqlpp::quote << block << ","
							<< user.userid << ")";
				}
				query.execute();
			} catch (const mysqlpp::BadQuery& er)
			{
				// Handle any query errors
				DEBUG("%d ACHTUNG Query error: %s", user.userid, er.what());
			} catch (const mysqlpp::BadConversion& er)
			{
				// Handle bad conversions
				DEBUG("%d ACHTUNG Conversion error: %s \tretrieved data size: %d , actual size: %d", user.userid,
						er.what(), er.retrieved, er.actual_size);
			} catch (const mysqlpp::Exception& er)
			{
				// Catch-all for any other MySQL++ exceptions
				DEBUG("%d ACHTUNG Error: %s", user.userid, er.what());
			}
		}
		else
		{

			DEBUG("%d moder: %d ACHTUNG block no url", user.userid, user.moder);
		}

		if (TaskURLs->size() > 0)
		{
			SAFE_DELETE(TaskURLs->at(0));
			TaskURLs->erase(TaskURLs->begin());
		}
		url = NULL;
		taskid = 0;
	}

	// пропускаем
	const char * next = evhttp_find_header(headers, "next");
	if (next /*&& (strlen(next) > 0)*/)
	{

		DEBUG("%d skip task %d", user.userid, taskid);
		if (TaskURLs->size() > 0)
		{
			SAFE_DELETE(TaskURLs->at(0));
			TaskURLs->erase(TaskURLs->begin());
		}
		taskid = 0;
	}

	char lbuf[200];
	const char * view = evhttp_find_header(headers, "view");
	if (view && (strlen(view) > 0)) // Пользователь ткнул в "следующая"
	{
		// Просмотр ссылки по серфингу
		if (TaskURLs->size() > 0)
		{
			url = TaskURLs->at(0);

			const char * rightvariant = evhttp_find_header(headers,
					"rightvariant");
			double paid = (question_right != -1 && (rightvariant != NULL)
					&& ((atoi(rightvariant) == question_right) || url->tasktype
							== 2)) ? 1 : 0;

			DEBUG("%d question_right: %d rightvariant: %s", user.userid, question_right,
					rightvariant);
			// все верно берем из поста
			const char * plottery = evhttp_find_header(headers, "lottery");
			int lott = 0;
			if (tasklottery[0])
				lott = (plottery != NULL) ? ((strcmp(plottery,
						tasklottery[rand() % 3]) == 0) ? 2 : 0) : 1;
			bool viewed = false;
			if (testurl)
			{
				if (paid)
				{

					DEBUG("Moder accepted %d", url->linkid);
					mysqlpp::Query query = con->query();
					query << "DELETE FROM `tasks_check_task` WHERE `linkid`="
							<< url->linkid << " AND `userid`=" << user.userid;
					query.execute();
					query << "DELETE FROM `tasks_mess` WHERE `linkid`="
							<< url->linkid;
					query.execute();
					query
							<< "UPDATE `tasks` SET `moderapprove`=1, `manualoff`=0 WHERE `linkid`="
							<< url->linkid;
					query.execute();
					query
							<< "UPDATE `auth` SET `countchecktask`=`countchecktask`-1 WHERE userid="
							<< user.userid << " and `countchecktask`>0";
					query.execute();

					query
							<< "INSERT INTO emailcontent(emailingid,content) VALUES ("
							<< url->linkid << "," << url->linkid << ")";
					mysqlpp::SimpleResult res = query.execute();
					if (res && (res.rows() != 0))
					{
						int contentid = res.insert_id();
						query
								<< "INSERT INTO emailqueue(target,userid,templateid,contentid) VALUES ("
								<< "'user'" << "," << url->userid << "," << 31
								<< "," << contentid << ")";
						query.execute();
					}
					if (TaskURLs->size() > 0)
					{
						SAFE_DELETE(TaskURLs->at(0));
						TaskURLs->erase(TaskURLs->begin());
					}
				}
			}
			else
				viewed = UrlTaskViewed(url, lott * paid, lott, 1);

			double earn = 0;
			if (viewed && paid)
			{
				earn = url->priceuser / 1000.0 * lott;
				user.balance += earn;
			}
			else
			{

				DEBUG("%d AFTER UrlTaskViewed viewed %d paid %f", user.userid, viewed,
						paid);
			}

			if (!viewed)
			{
				if (!testurl)
					mess = (char*) "ErrViewPage";
				else
				{
					if (paid)
						mess = (char*) "TaskChecked";
					else
						mess = (char*) "TaskNotChecked";
				}
			}
			else
			{
				SAFE_DELETE(TaskURLs->at(0));
				TaskURLs->erase(TaskURLs->begin());
				sprintf(lbuf, "Earn: %1.4f$", earn);
				mess = &lbuf[0];
			}
		}
		taskid = 0;
	}
	else
		mess = (char*) "";

	if (!taskid)
	{
		if ((user.moder) && (TaskURLs->size() == 0))
		{

			DEBUG("user is moder");
			mysqlpp::Query query = con->query();
			query << "select tasks.* from tasks, tasks_check_task ch "
					<< "where tasks.linkid=ch.linkid and ch.userid="
					<< user.userid;
			mysqlpp::UseQueryResult res = query.use();
			mysqlpp::Row row;
			while (row = res.fetch_row())
			{
				//int userid = atoi(row["userid"].c_str());
				Url * url = new Url();
				url->populate(row);

				DEBUG("%d Task for Moder url: %d",user.userid, url->linkid);
				TaskURLs->push_back(url);
			}
			if (TaskURLs->size() > 0)
				testurl = true;
			else
				testurl = false;
			if (TaskURLs->size() > 1)
				sort(TaskURLs->begin(), TaskURLs->end(), taskscmp);

			DEBUG("%d Moder TaskList size %d %s", user.userid,
					TaskURLs->size(), (testurl?"true":"false"));
		}

		if (TaskURLs->size() == 0)
			GetTaskListURLs();

		bool wdo = true;
		while (wdo)
		{
			// Получаем новый URL для просмотра
			url = GetURL(TaskURLs, true);
			if (url)
			{
				if (url->show != 0)
				{

					DEBUG("%d erase task url %d", user.userid, url->linkid);
					SAFE_DELETE(TaskURLs->at(0));
					TaskURLs->erase(TaskURLs->begin());
				}
				else
					wdo = false;
			}
			else
			{
				if (TaskURLs->size() > 0)
				{

					DEBUG("%d erase url becouse is not checked %d", user.userid, TaskURLs->at(0)->linkid);
					SAFE_DELETE(TaskURLs->at(0));
					TaskURLs->erase(TaskURLs->begin());
				}
				else
					wdo = false;
			}
		}

		if (url)
		{
			taskid = url->linkid;

			if (!testurl)
				ShowTaskURL(url);

			Url * turl = TaskURLs->at(0);
			turl->show = url->show;
			turl->logid = url->logid;

			// Получаем referer для текущей ссылки
			SAFE_FREE(url->referer);
			if (url->hasreferer)
			{
				int rnd_ref = rand() % (url->hasreferer);
				mysqlpp::Query query = con->query();
				query << "SELECT referer FROM tasks_referer_mem WHERE linkid="
						<< url->linkid << " LIMIT " << rnd_ref << ",1";
				mysqlpp::StoreQueryResult res = query.store();
				if (res && (res.num_rows() > 0))
				{
					mysqlpp::Row row = res.at(0);
					url->referer = strdup(row["referer"].c_str());
					//				res.purge();
				}
				else
				{

					DEBUG("%d TASK REFFERER NO RES: %s", user.userid,
							query.error());
				}
			}

			// Получаем точку входа для текущей ссылки
			if (url->cntinputpoint)
			{
				int rnd_inp = rand() % (url->cntinputpoint);
				mysqlpp::Query query = con->query();
				query << "SELECT url FROM tasks_inputpoint_mem WHERE linkid="
						<< url->linkid << " LIMIT " << rnd_inp << ",1";
				mysqlpp::StoreQueryResult res = query.store();
				if (res && (res.num_rows() > 0))
				{
					mysqlpp::Row row = res.at(0);
					SAFE_FREE(url->url);
					url->url = strdup(row["url"].c_str());
					//				res.purge();
				}
				else
				{

					DEBUG("%d INPUTPOINT NO RES: %s", user.userid, query.error());
				}
			}
		}
		else
		{

			DEBUG("%d TASKHANDLE NO URL", user.userid);
		}
	}

	if (!url)
	{ // Просмотр завершен!
		// Освобождаем прошлую лотерею
		SAFE_FREE(tasklottery[0]);
		SAFE_FREE(tasklottery[1]);
		SAFE_FREE(tasklottery[2]);

		taskid = 0;

		mysqlpp::Query query = con->query();
		query << "SELECT balance FROM user WHERE userid=" << user.userid;
		mysqlpp::StoreQueryResult res = query.store();
		if (res && (res.num_rows() == 1))
		{
			mysqlpp::Row row = res.at(0);
			user.balance = atof(row["balance"].c_str());
		}
		else
		{

			DEBUG("%d TASKHANDLE3 NO RES: %s", user.userid, query.error());
		}

		buffer << "<vipip>" << "<endsurf>EndView</endsurf>" << "<balance>"
				<< fixed << setprecision(4) << user.balance << "</balance>"
				<< "<banner1>http://"SERVISE_HOST"/banners/app/load?type=3</banner1>"
				<< "</vipip>";
	}
	else
	{
		// Освобождаем прошлую лотерею
		SAFE_FREE(tasklottery[0]);
		SAFE_FREE(tasklottery[1]);
		SAFE_FREE(tasklottery[2]);
		// Заполняем лотерею
		tasklottery[0] = str_rand(3, "acdefghmnpqstwyz2345789");
		tasklottery[1] = str_rand(3, "acdefghmnpqstwyz2345789");
		tasklottery[2] = str_rand(3, "acdefghmnpqstwyz2345789");

		if (url->tasktype == 1)
		{
			// Получаем вопрос и варианты ответов к нему.
			mysqlpp::Query query = con->query();
			query << "SELECT * FROM task_questions WHERE linkid="
					<< url->linkid << " ORDER BY RAND() LIMIT 1";
			mysqlpp::StoreQueryResult res = query.store();
			if (res && (res.num_rows() > 0))
			{
				mysqlpp::Row qrow = res.at(0);
				if (!url->question)
					url->question = new Question();
				url->question->question = strdup(qrow["question"].c_str());
				url->question->comment = strdup(qrow["comment"].c_str());
				int taskquestionid = atoi(qrow["taskquestionid"].c_str());
				//				res.purge();

				// варианты ответа к нему.
				query << "SELECT * FROM task_variants WHERE taskquestionid="
						<< taskquestionid << " ORDER BY RAND()";
				int counter = -1;
				mysqlpp::UseQueryResult res = query.use();
				while (mysqlpp::Row row = res.fetch_row())
				{
					counter++;
					std::string variant(row["variant"].c_str());
					replace(variant.begin(), variant.end(), '\\', ' ');

					variants << "<variant>" << variant.c_str()
							<< "</variant>\n";
					if (atoi(row["right"].c_str()) == 1)
						question_right = counter;
				}
				if (counter == -1)
				{
					question_right = -1;

					DEBUG("%s TASKHANDLE3 NO RES: %s", user.userid,
							query.error());
				}
				url->question->variants = strdup(variants.str().c_str());
			}
			else
			{

				DEBUG("%d TASKHANDLE4 NO RES: %s", user.userid, query.error());
			}
		}
		else
		{
			question_right = 0;
			mysqlpp::Query query = con->query();
			query << "SELECT * FROM task_clickurl WHERE linkid=" << url->linkid
					<< " ORDER BY RAND() LIMIT 1";
			mysqlpp::StoreQueryResult res = query.store();
			if (res && (res.num_rows() == 1))
			{
				mysqlpp::Row row = res.at(0);
				if (!url->question)
					url->question = new Question();
				url->question->url = strdup(row["url"].c_str());
				std::string comment(row["comment"].c_str());
				replace(comment.begin(), comment.end(), '\\', ' ');
				url->question->question = strdup(comment.c_str());
				url->question->comment = strdup(row["url"].c_str()); // 'comment'	=> 'LinkToClick: '. $q['url']);
				//				res.purge();
			}
			else
			{

				DEBUG("%d TASKHANDLE5 NO RES: %s", user.userid, query.error());
			}
		}
		buffer << "<vipip>" << "<url>" << url->url << "</url>" << "<tasktype>"
				<< url->tasktype << "</tasktype>" << "<referer>"
				<< (url->referer ? url->referer : "") << "</referer>"
				<< "<lottery>" << tasklottery[0] << "|" << tasklottery[1]
				<< "|" << tasklottery[2] << "</lottery>"
				<< "<banner1>http://"SERVISE_HOST"/banners/app/load?type=3</banner1>"
				<< "<message>" << mess << "</message>" << "<version>"
				<< app_version << "</version>" << "<timer>" << url->timer
				<< "</timer>" << "<balance>" << fixed << setprecision(4)
				<< user.balance << "</balance>" << "<question>"
				<< (testurl ? "[ТЕСТИРОВАНИЕ]" : "") << url->question->question
				<< "</question>" << "<comment>" << url->question->comment
				<< "</comment>";
		if (url->tasktype == 1)
			buffer << "<variants>" << variants.str().c_str() << "</variants>";
		else
			buffer << "<clickurl>" << url->question->url << "</clickurl>"
					<< "<clicktitle>" << url->question->url << "</clicktitle>"
					<< "<auto>0</auto>";
		buffer << "<counters>" << "<item>http://counter.yadro.ru/hit?t14.6;"
				<< rand() << "</item>"
				<< "<item>http://counter.rambler.ru/top100.cnt?" << rand()
				<< "</item>"
				<< "<item>http://d1.c4.b1.a1.top.list.ru/counter?t=56;rand="
				<< rand() << "</item>" << "</counters>" << "</vipip>";
	}

	return strdup(buffer.str().c_str());
}

// Новый ShowURL
int AppSurfing::ShowURL(Url *url)
{
	int logid = 0;
	DEBUG("%d AppSurfing::ShowURL", user.userid);

	if (url->show == 0)
	{
		char today[80];
		memset(today, '\0', 80 * sizeof(char));
		strftime(today, 80, "%Y%m%d", timeinfo);
		char cTime[80];
		memset(cTime, '\0', 80 * sizeof(char));
		strftime(cTime, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
		char * proxyip = (char*) "";

		// TODO доделать
		/*if (isset($_SERVER['X-Forwarded-For']))
		 {
		 preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/', $_SERVER['X-Forwarded-For'], $proxyipa);
		 $proxyip = $proxyipa[0];
		 }*/

		mysqlpp::Query query = con->query();
		query
				<< "INSERT INTO links_log(userid,linkid,ipaddr,proxyip,sid,`when`) VALUES ("
				<< user.userid << "," << url->linkid << "," << user.remoteAddr
				<< "," << inet_addr(proxyip) << "," << mysqlpp::quote
				<< session_id << "," << mysqlpp::quote << cTime << ")";
		mysqlpp::SimpleResult res = query.execute();
		if (res && (res.rows() != 0))
		{
			logid = res.insert_id();

			DEBUG("%d ShowURL HAVE RES %d %d", user.userid, url->linkid, url->show);
			if (url->costtype == 1)
			{
				try
				{
					// Снимаем баланс со ссылки
					mysqlpp::Query query = con->query();
					query
							<< "UPDATE links SET balance=balance-1,enabled=IF(enabled, balance>0, 0) WHERE linkid="
							<< url->linkid;
					query.execute();
					//query = con->query();
					query
							<< "UPDATE links_mem SET balance=balance-1,enabled=IF(enabled, balance>0, 0), visitcacheday_visits=visitcacheday_visits+1, visitcachehour_visits=visitcachehour_visits+1 WHERE linkid="
							<< url->linkid;
					query.execute();
				} catch (const mysqlpp::BadQuery& er)
				{
					// Handle any query errors
					FATAL("%d ACHTUNG Query error: %s", user.userid, er.what());
					return 0;
				} catch (const mysqlpp::BadConversion& er)
				{
					// Handle bad conversions
					FATAL("%d ACHTUNG Conversion error: %s \tretrieved data size: %d, actual size: %d", user.userid,
							er.what(), er.retrieved, er.actual_size);
					return 0;
				} catch (const mysqlpp::Exception& er)
				{
					// Catch-all for any other MySQL++ exceptions
					FATAL("%d ACHTUNG Error: %s", user.userid, er.what());
					return 0;
				}
			}
			// Всё сделали -- обновим кеш просмотров
			int uniq = 0; // считаем неуникальным просмотром

			// 1. visitcacheuser (linkid, userid, day, visits)
			mysqlpp::Query query = con->query();
			query << "UPDATE visitcacheuser SET visits = visits + 1 "
					<< "WHERE linkid=" << url->linkid << " AND " << "userid="
					<< user.userid << " AND " << "day=" << mysqlpp::quote
					<< today;
			res = query.execute();
			if (res && (res.rows() == 0))
			{
				mysqlpp::Query query = con->query();
				query
						<< "INSERT INTO visitcacheuser(linkid, userid, day, visits) "
						<< "VALUES (" << url->linkid << "," << user.userid
						<< "," << mysqlpp::quote << today << "," << "1)";
				res = query.execute();
				uniq = 1; // если строку добавили -- просмотр уникален был
			}
				else
				WARN("%d ShowURL visitcacheuser updated %d", user.userid, res.rows());
			int idx = 0;
			CheckUrl *churl = NULL;
			for (checkiter element = CheckURLs->begin(); element
					< CheckURLs->end(); element++)
			{
				churl = (*element);
				if ((churl) && (churl->linkid == url->linkid))
				{
					churl->count++;
					churl->day_visits++;
					churl->balance--;
					if (uniq > 0)
						churl->uniq++;
					break;
				}
				idx++;
			}

			// переменные которые необходимо заполнить
			// переменные
			try
			{
				query << "CALL update_visits(" << url->linkid << ","
						<< user.userid << "," << url->surfid << ","
						<< user.user_location << "," << mysqlpp::quote << today
						<< "," << timeinfo->tm_hour << "," << user.remoteAddr
						<< "," << uniq << ")";
				query.execute();

				// 3. visitcacheday  (linkid, day, visits, visits_uniq)
				query << "UPDATE visitcacheday SET visits = visits + 1, "
						<< "visits_uniq = visits_uniq + " << uniq << " "
						<< "WHERE linkid=" << url->linkid << " AND " << "day="
						<< mysqlpp::quote << today;
				res = query.execute();
				if (res.rows() == 0)
				{
					query
							<< "INSERT INTO visitcacheday(linkid, day, visits, visits_uniq) "
							<< "VALUES (" << url->linkid << ","
							<< mysqlpp::quote << today << "," << "1," << uniq
							<< ")";
					res = query.execute();
				}
					else
					DEBUG("%d ShowURL visitcacheday updated %d", user.userid,
							res.rows());

				// 4. visitcachehour (linkid, day, hour, visits)
				query << "UPDATE visitcachehour SET visits = visits + 1 "
						<< "WHERE linkid=" << url->linkid << " AND " << "hour="
						<< timeinfo->tm_hour << " AND " << "day="
						<< mysqlpp::quote << today;
				res = query.execute();
				if (res.rows() == 0)
				{
					//mysqlpp::Query query = con->query();
					query
							<< "INSERT INTO visitcachehour(linkid, hour, day, visits) "
							<< "VALUES (" << url->linkid << ","
							<< timeinfo->tm_hour << "," << mysqlpp::quote
							<< today << "," << "1)";
					res = query.execute();
				}
					else
					WARN("%d ShowURL visitcachehour updated %d", user.userid, res.rows());
			} catch (const mysqlpp::BadQuery& er)
			{
				// Handle any query errors
				FATAL("%d ACHTUNG Query error: %s", user.userid, er.what());
				return 0;
			} catch (const mysqlpp::BadConversion& er)
			{
				// Handle bad conversions
				FATAL("%d ACHTUNG Conversion error: %s \tretrieved data size: %d, actual size: %d", user.userid,
						er.what(), er.retrieved, er.actual_size);
				return 0;
			} catch (const mysqlpp::Exception& er)
			{
				// Catch-all for any other MySQL++ exceptions
				FATAL("%d ACHTUNG Error: %s", user.userid, er.what());
				return 0;
			}

		}
		else
		{

			WARN("%d ShowURL NO RES: %s", user.userid, query.error());
		}
	}
	return logid;
}

//   Регистрация показа ссылки пользователю.
//   С баланса ссылки снимается сумма, запомианется что ссылка смотрена,
//   обновляются кеши.

bool AppSurfing::ShowTaskURL(Url *url)
{

	DEBUG("%d ShowTaskURL", user.userid);
	if (url->show == 0)
	{
		char today[80];
		memset(today, '\0', 80 * sizeof(char));
		strftime(today, 80, "%Y%m%d", timeinfo);
		char cTime[80];
		memset(cTime, '\0', 80 * sizeof(char));
		strftime(cTime, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
		char * proxyip = (char*) "";

		mysqlpp::Query query = con->query();
		query
				<< "INSERT INTO tasks_log(userid,linkid,ipaddr,proxyip,sid,`when`) VALUES ("
				<< user.userid << "," << url->linkid << "," << user.remoteAddr
				<< "," << inet_addr(proxyip) << "," << mysqlpp::quote
				<< session_id << "," << mysqlpp::quote << cTime << ")";

		mysqlpp::SimpleResult res = query.execute();
		if (res && (res.rows() != 0))
		{
			url->show = now;
			url->logid = res.insert_id();

			if (url->costtype == 1)
			{
				// Снимаем баланс со ссылки
				mysqlpp::Query query = con->query();
				query
						<< "UPDATE tasks SET balance=balance-1,enabled=IF(enabled, balance>0, 0) WHERE linkid="
						<< url->linkid;
				res = query.execute();
				query = con->query();
				query
						<< "UPDATE tasks_mem SET balance=balance-1,enabled=IF(enabled, balance>0, 0), taskcacheday_visits=taskcacheday_visits+1, taskcachehour_visits=taskcachehour_visits+1 WHERE linkid="
						<< url->linkid;
				res = query.execute();
			}

			// Всё сделали -- обновим кеш просмотров
			int uniq = 0; // считаем неуникальным просмотром

			// 1. taskcacheuser (linkid, userid, day, visits)
			mysqlpp::Query query = con->query();
			query << "UPDATE taskcacheuser SET visits = visits + 1 "
					<< "WHERE linkid=" << url->linkid << " AND " << "userid="
					<< user.userid << " AND " << "day=" << mysqlpp::quote
					<< today;
			res = query.execute();
			if (res && (res.rows() == 0))
			{
				mysqlpp::Query query = con->query();
				query
						<< "INSERT INTO taskcacheuser(linkid, userid, day, visits) "
						<< "VALUES (" << url->linkid << "," << user.userid
						<< "," << mysqlpp::quote << today << "," << "1)";
				res = query.execute();
				uniq = 1; // если строку добавили -- просмотр уникален был
			}
				else
				DEBUG("%d ShowTaskURL taskcacheuser updated %d", user.userid, res.rows());

			int idx = 0;
			CheckUrl *churl = NULL;
			for (checkiter element = CheckTaskURLs->begin(); element
					< CheckTaskURLs->end(); element++)
			{
				churl = (*element);
				if ((churl) && (churl->linkid == url->linkid))
				{
					churl->count++;
					churl->day_visits++;
					churl->balance--;
					if (uniq > 0)
						churl->uniq++;
					break;
				}
				idx++;
			}
			// taskcacheuserlastday (linkid, userid, day, visits)
			query << "REPLACE INTO taskcacheuserlastday VALUES(" << url->linkid
					<< "," << user.userid << "," << mysqlpp::quote << today
					<< ")";
			res = query.execute();
			// 2. taskcacheip (linkid, ip, day, visits)
			//mysqlpp::Query query = con->query();
			query << "UPDATE taskcacheip SET visits = visits + 1 "
					<< "WHERE linkid=" << url->linkid << " AND " << "ip="
					<< user.remoteAddr << " AND " << "day=" << mysqlpp::quote
					<< today;
			res = query.execute();
			if (res.rows() == 0)
			{
				query << "INSERT INTO taskcacheip(linkid, ip, day, visits) "
						<< "VALUES (" << url->linkid << "," << user.remoteAddr
						<< "," << mysqlpp::quote << today << "," << "1)";
				res = query.execute();
			}
				else
				DEBUG("%d ShowTaskURL taskcacheip updated %d", user.userid,
						res.rows());

			// 3. taskcacheday  (linkid, day, visits, visits_uniq)
			//mysqlpp::Query query = con->query();
			query << "UPDATE taskcacheday SET visits = visits + 1, "
					<< "visits_uniq = visits_uniq + " << uniq << " "
					<< "WHERE linkid=" << url->linkid << " AND " << "day="
					<< mysqlpp::quote << today;
			res = query.execute();
			if (res.rows() == 0)
			{
				query
						<< "INSERT INTO taskcacheday(linkid, day, visits, visits_uniq) "
						<< "VALUES (" << url->linkid << "," << mysqlpp::quote
						<< today << "," << "1," << uniq << ")";
				res = query.execute();
			}
				else
				DEBUG("%d ShowTaskURL taskcacheday updated %d", user.userid,
						res.rows());

			// 4. taskcachehour (linkid, day, hour, visits)
			//mysqlpp::Query query = con->query();
			query << "UPDATE taskcachehour SET visits = visits + 1 "
					<< "WHERE linkid=" << url->linkid << " AND " << "hour="
					<< timeinfo->tm_hour << " AND " << "day=" << mysqlpp::quote
					<< today;
			res = query.execute();
			if (res.rows() == 0)
			{
				//mysqlpp::Query query = con->query();
				query
						<< "INSERT INTO taskcachehour(linkid, hour, day, visits) "
						<< "VALUES (" << url->linkid << ","
						<< timeinfo->tm_hour << "," << mysqlpp::quote << today
						<< "," << "1)";
				res = query.execute();
			}
				else
				DEBUG("%d ShowTaskURL taskcachehour updated %d", user.userid, res.rows());

			// 5. taskcachetype (taskid, day, visits, linkid)
			//mysqlpp::Query query = con->query();
			query << "UPDATE taskcachetype SET visits = visits + 1 "
					<< "WHERE taskid=" << url->taskid << " AND " << "day="
					<< mysqlpp::quote << today << " AND " << "linkid="
					<< url->linkid;
			res = query.execute();
			if (res.rows() == 0)
			{
				query
						<< "INSERT INTO taskcachetype(taskid, day, visits, linkid) "
						<< "VALUES (" << url->taskid << "," << mysqlpp::quote
						<< today << "," << "1," << url->linkid << ")";
				res = query.execute();

				DEBUG("%d ShowTaskURL taskcachetype inserted %d", user.userid, res.rows());
			}
				else
				DEBUG("%d ShowTaskURL taskcachetype updated %d",  user.userid, res.rows());

			query << "UPDATE taskgeostat "
					<< "SET visits=visits+1, visits_uniq=visits_uniq+" << uniq
					<< " " << "WHERE day=" << mysqlpp::quote << today
					<< " AND cityid=" << user.user_location << " "
					<< " AND linkid=" << url->linkid;
			res = query.execute();
			if (res.rows() == 0)
			{
				query
						<< "INSERT INTO taskgeostat(day, cityid, linkid, visits, visits_uniq) "
						<< "VALUES (" << mysqlpp::quote << today << ","
						<< user.user_location << "," << url->linkid << ","
						<< "1," << uniq << ")";
				res = query.execute();

				DEBUG("%d ShowTaskURL taskgeostat inserted %d", user.userid, res.rows());
			}
				else
				DEBUG("%d ShowTaskURL taskgeostat updated %d", user.userid, res.rows());
		}
		else
		{

			DEBUG("%d ShowTaskURL NO RES: %s", user.userid, query.error());
		}
		//		SAFE_FREE(today);
		//		SAFE_FREE(cTime);
		return (res != false);
	}
	else
	{

		DEBUG("%d AppSurfing::ShowTaskURL TIME ALREADY SETED", user.userid);
		return false;
	}
}

// Самая весёлая функция.
//	 Поиск доступных ссылок производится не чаще, чем раз в 5 минут, для
// снижения нагрузки на сервер (да и для даже HIT серфинга просмотр одним
// пользователем подряд одной и той же ссылки -- смысла не имеет)
//	 Исключение: если первая из ссылок, которую надо бы сейчас посетить
// оказывается отключенной, то производится внеплановый перепоиск.
mysqlpp::Row AppSurfing::GetListURLs(int autosurf)
{

	DEBUG("%d GetListURLs", user.userid);

	char today[80];
	strftime(today, 80, "%Y-%m-%d", timeinfo);
	mysqlpp::Query query = con->query();
	int proxy = 0;
	//	int trackuserip = 0;
	mysqlpp::Row row;

	//	if ((AppURLs->size() == 0) || (autosurf && (AutoAppURLs->size()
	//			== 0)))
	//	{
	// Что выбираем -- только информацию о самой ссылке
	query << "SELECT links_mem.* FROM links_mem "
			<< "LEFT JOIN placetarget_ci ON (placetarget_ci.placetargetid=links_mem.placetargetid AND placetarget_ci.target = "
			<< user.user_location << ") "
			<< "LEFT JOIN visitcacheuser ON (visitcacheuser.linkid=links_mem.linkid AND visitcacheuser.userid="
			<< user.userid << " AND visitcacheuser.day=" << mysqlpp::quote
			<< today << ") "
			<< "LEFT JOIN visitcacheip ON (visitcacheip.linkid=links_mem.linkid AND visitcacheip.ip="
			<< user.remoteAddr << " AND visitcacheip.day=" << mysqlpp::quote
			<< today << ") "
			<< "LEFT JOIN links_block ON (links_block.linkid=links_mem.linkid AND links_block.userid="
			<< user.userid << ") " << "WHERE (enabled=1) AND ";
	// блокировка публичных прокси
	if (proxy == 1)
		query << " (allowproxy=1) AND ";
	// Поддержка блокировки ссылки самим юзером
	query << "(links_block.description IS NULL) AND ";
	// Показ сайтов без фрейма
	if (!user.advside)
		query << "(links_mem.advsidecheck=0  OR avto='1') AND ";
	// Показ сайтов для лиц старше 18
	if (!user.pornosite)
		query << "links_mem.pornosite=0 AND ";

	query << "(links_mem.userid<>" << user.userid << " OR hide=0) AND " << // скрывать ссылку от самого себя

			// Фильтрация по параметрам самой ссылки
			// В случае surfid=1: вип серфинг, учитываются все ограничения
			// В случае surfid=2: стандарт серфинг, лимита по юзеру нет, только ip
			// В случае surfid=3: лайт серфинг, учитывается все
			// В случае surfid=4: хит серфинг, ограничения на число посещений человеком нет
			// В случае surfid=5: автосерфинг, учитываются все ограничения
			"((" << user.showcat << " & (1 << code))<>0 OR avto = '1') AND "
			<< "((maxshowday = 0) OR "
			<< "(!links_mem.reginterval AND maxshowday > visitcacheday_visits) OR (maxshowday*"
			<< beginday << " > visitcacheday_visits)) AND "
			<< "((code=4) OR (code=2) OR (visitcacheuser.visits is null) OR (maxshowuser > visitcacheuser.visits)) AND "
			<< "((code=4) OR (visitcacheip.visits is null) OR (maxshowuser > visitcacheip.visits)) AND "
			<<
			// Таймтаргеттинг
			"((timelimit_timelimitid IS NULL) OR ("
			<< "(day_visits IS NULL) AND (hour_visits IS NULL) AND "
			<< "((timelimit_visits=0) OR "
			<< "(timelimit_visits > visitcachehour_visits AND (!links_mem.reginterval OR (timelimit_visits*"
			<< beginhour << " > visitcachehour_visits))))" << ") "

	<< " OR ((day_visits IS NOT NULL) AND (hour_visits IS NULL) AND "
			<< "(day_visits=0 OR "
			<< "(day_visits > visitcacheday_visits AND (!links_mem.reginterval OR (day_visits*"
			<< beginday << " > visitcacheday_visits)))) ) "

	<< " OR ((hour_visits IS NOT NULL) AND " << "(hour_visits=0 OR  "
			<< "(hour_visits > visitcachehour_visits AND (!links_mem.reginterval OR (hour_visits*"
			<< beginhour << " > visitcachehour_visits)))) "

	<< " )) AND "

	// Местотаргеттинг
			<< "((!links_mem.placetargetid) OR (placetarget_ci.target = "
			<< user.user_location << ")) AND " << "(1=1) ";


	mysqlpp::UseQueryResult res = query.use();
	// Заполнение всего списка
	while (row = res.fetch_row())
	{
		//int surfid = atoi(row["surfid"].c_str());
		int linkid = atoi(row["linkid"].c_str());
		int autosurf = atoi(row["avto"].c_str());
		int balance = atoi(row["balance"].c_str());
		int
				time_limit = (strcmp(row["timelimit_visits"].c_str(), "NULL")
						== 0) ? -RAND_MAX : atoi(
						row["timelimit_visits"].c_str());
		int maxshowday =
				(strcmp(row["maxshowday"].c_str(), "NULL") == 0) ? -RAND_MAX
						: atoi(row["maxshowday"].c_str());
		int
				day_visits =
						/*(strcmp(row["visitcacheday_visits"].c_str(), "NULL"))?-RAND_MAX:*/atoi(
								row["visitcacheday_visits"].c_str());
		int day_limit =
				(strcmp(row["day_visits"].c_str(), "NULL") == 0) ? -RAND_MAX
						: atoi(row["day_visits"].c_str());
		int hour_limit =
				(strcmp(row["hour_visits"].c_str(), "NULL") == 0) ? -RAND_MAX
						: atoi(row["hour_visits"].c_str());

		/*DEBUG("%d CheckURLs TEST url: %d time_limit %s maxshowday %s day_limit %s hour_limit %s",
		 user.userid, linkid, row["timelimit_visits"].c_str(), row["maxshowday"].c_str(), row["day_visits"].c_str(), row["hour_visits"].c_str());*/
		//767 CheckURLs TEST url: 48709 time_limit NULL maxshowday 0 day_limit NULL hour_limit NULL


		//int hasreferer = atoi(row["hasreferer"].c_str());
		Url * url = NULL;
		if (autosurf != 1)
		{
			url = url_find(AppURLs, linkid);
			if (!url)
			{
				url = new Url();
				url->populate(row);
				url->gettime = now;
				//DEBUG("%d GetListURLs fulllist app url: %d", user.userid, url->linkid);
				AppURLs->push_back(url);
			}
		}

		// Автосерф
		if (/*autosurf && */(autosurf == 1))
		{
			url = url_find(AutoAppURLs, linkid);
			if (!url)
			{
				url = new Url();
				url->populate(row);
				url->gettime = now;
				//DEBUG("%d GetListURLs fulllist auto url: %d", user.userid, url->linkid);
				AutoAppURLs->push_back(url);
			}
		}
		CheckUrl *churl = check_find(CheckURLs, linkid);
		if (!churl)
		{
			churl = new CheckUrl();
			churl->linkid = linkid;
			churl->balance = balance;
			churl->time_limit = (time_limit == 0) ? RAND_MAX : time_limit;
			churl->maxshowday = (maxshowday == 0) ? RAND_MAX : maxshowday;
			churl->day_visits = day_visits;
			churl->day_limit = (day_limit == 0) ? RAND_MAX : day_limit;
			churl->hour_limit = (hour_limit == 0) ? RAND_MAX : hour_limit;
			churl->hour = timeinfo->tm_hour;
			churl->day = timeinfo->tm_mday;
			CheckURLs->push_back(churl);

			DEBUG("%d CheckURLs ADD url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
					user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
		}
		else
		{
			churl->balance = balance;
			churl->time_limit = (time_limit == 0) ? RAND_MAX : time_limit;
			churl->maxshowday = (maxshowday == 0) ? RAND_MAX : maxshowday;
			churl->day_limit = (day_limit == 0) ? RAND_MAX : day_limit;
			churl->hour_limit = (hour_limit == 0) ? RAND_MAX : hour_limit;
		}
	}

	DEBUG("%d GetListURLs fulllist size %d %d", user.userid, AppURLs->size(),
			AutoAppURLs->size());

	DEBUG("%d CheckURLs fulllist SIZE %d", user.userid, CheckURLs->size());

	if (AppURLs->size() > 1)
		sort(AppURLs->begin(), AppURLs->end(), linkscmp);
	if (AutoAppURLs->size() > 1)
		sort(AutoAppURLs->begin(), AutoAppURLs->end(), linkscmp);
	urls_show(AppURLs, user.userid);
	//	}
	return row;
}

/*mysqlpp::Row*/bool AppSurfing::CheckURL(Url * url)
{

	DEBUG("%d CheckURLs SIZE %d", user.userid, CheckURLs->size());

	/*char buffer[80];
	 strftime(buffer, 80, "%Y-%m-%d", timeinfo);
	 mysqlpp::UseQueryResult res;*/
	if (url)
	{
		int idx = 0;
		CheckUrl *churl = NULL;
		for (checkiter element = CheckURLs->begin(); element < CheckURLs->end(); element++)
		{
			churl = (*element);
			if ((churl) && (churl->linkid == url->linkid))
			{
				if ((churl->balance <= 0) || ((churl->time_limit != -RAND_MAX)
						&& (churl->time_limit <= churl->count))
						|| ((churl->maxshowday != -RAND_MAX)
								&& (churl->maxshowday <= churl->day_visits))
						|| ((churl->day_limit != -RAND_MAX)
								&& (churl->day_limit <= churl->day_visits))
						|| ((churl->hour_limit != -RAND_MAX)
								&& (churl->hour_limit <= churl->count))
						|| (churl->day != timeinfo->tm_mday) || (churl->hour
						!= timeinfo->tm_hour))
				{
					/*mysqlpp::Query query = con->query();
					 mysqlpp::SimpleResult res;
					 query << "UPDATE taskcacheday " << "SET visits = visits + " << churl->day_count << ", "
					 //<< "visits_uniq = visits_uniq + " << uniq << " "
					 << "WHERE linkid=" << churl->linkid << " AND " << "day="
					 << mysqlpp::quote << today; //TODO: не today а из churl
					 res = query.execute();
					 if (res.rows() == 0)
					 {
					 query
					 << "INSERT INTO taskcacheday(linkid, day, visits, visits_uniq) "
					 << "VALUES (" << churl->linkid << "," << mysqlpp::quote
					 << today << "," << churl->day_count << uniq << ")"; //TODO: не today а из churl
					 res = query.execute();
					 }
					 else
					 DEBUG("%d ShowTaskURL taskcacheday updated %d", user.userid,
					 res.rows());

					 // 4. taskcachehour (linkid, day, hour, visits)
					 //mysqlpp::Query query = con->query();
					 query << "UPDATE taskcachehour SET visits = visits + " << churl->hour_count
					 << "WHERE linkid=" << churl->linkid << " AND " << "hour="
					 << churl->hour << " AND " << "day=" << mysqlpp::quote
					 << today; //TODO: не today а из churl
					 res = query.execute();
					 if (res.rows() == 0)
					 {
					 //mysqlpp::Query query = con->query();
					 query
					 << "INSERT INTO taskcachehour(linkid, hour, day, visits) "
					 << "VALUES (" << churl->linkid << ","
					 << churl->hour << "," << mysqlpp::quote << today
					 << "," << churl->hour_count << ")"; //TODO: не today а из churl
					 res = query.execute();
					 }
					 else
					 DEBUG("%d ShowTaskURL taskcachehour updated %d", user.userid, res.rows());*/

					DEBUG("%d CheckURLs REMOVED url: %d balance %d time_limit %d maxshowday %d day_limit %d day_visits %d hour_limit %d count %d uniq %d",
							user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->day_visits, churl->hour_limit, churl->count, churl->uniq);
					SAFE_DELETE(CheckURLs->at(idx));
					CheckURLs->erase(CheckURLs->begin() + idx);
					return false;
				}
				if ((churl) && (churl->balance > 0))
				{
					if (churl->maxshowday != -RAND_MAX)
					{
						if (url->reginterval == 0)
						{
							if (churl->maxshowday > churl->day_visits)
							{

								DEBUG("%d CheckURLs MAXSHOWDAY url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
						else
						{
							if ((churl->maxshowday * beginday)
									> churl->day_visits)
							{

								DEBUG("%d CheckURLs MAXSHOWDAY REG url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}

					}
					else if (churl->hour_limit != -RAND_MAX)
					{
						if (url->reginterval == 0)
						{
							if (churl->hour_limit > churl->count)
							{

								DEBUG("%d CheckURLs HOUR url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
						else
						{
							if ((churl->hour_limit * beginhour) > churl->count)
							{

								DEBUG("%d CheckURLs HOUR REG url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
					}
					else if (churl->day_limit != -RAND_MAX)
					{
						if (url->reginterval == 0)
						{
							if (churl->day_limit > churl->day_visits)
							{

								DEBUG("%d CheckURLs DAY url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
						else
						{
							if ((churl->day_limit * beginday)
									> churl->day_visits)
							{

								DEBUG("%d CheckURLs DAY REG url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}

					}
					else if (churl->time_limit != -RAND_MAX)
					{
						if (churl->time_limit > churl->count)
						{

							DEBUG("%d CheckURLs TIMELIMIT url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
									user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
							return true;
						}
					}
					else
					{

						DEBUG("%d CheckURLs BALANCE url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
								user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
						return true;
					}
				}
				break;
			}
			idx++;
		}
	}

	DEBUG("%d CheckURLs FALSE FOR %d", user.userid, url->linkid);
	return /*res.fetch_row(); */false;
}
//   Возвращает URL для просмотра.
//   В зависимости от параметра isnew -- новый или старый.
//
//   Если требуется не новая ссылка -- то возвращается 0й элемента массива
//   загруженных URLов. (то есть ссылку просит нижестоящий фрейм).
//
//   Если требуется новая ссылка -- то каждый раз 0й элемент проверяется на
//   доступность для просмотра этой ссылки. Если недоступна -- она удаляется и
//   пробуем дальше. Если ссылки закончились -- просим GetListURLs переполучить
//   ссылки (возможно появились новые доступные).
//   Если же и тогда нету -- ну нет так нет, возвращаем FALSE;

Url* AppSurfing::GetURL(urlvector * URLs, bool isTask)
{
	if (URLs->size() > 0)
	{
		int show = 0;
		Url * url = URLs->at(0);

		if (url && url->show)
			show = url->show;
			else
			DEBUG("%d URL NO SHOW %d", user.userid, url->linkid);

		mysqlpp::Row row;
		bool check = false;
		if (isTask)
		{
			if (testurl)
			{

				DEBUG("%d IS MODER TASK %d", user.userid, url->linkid);
				return url;
			}
				else
				DEBUG("%d IS TASK", user.userid);
			/*row = */check = CheckTaskURL(url);
		}
		else
			/*row =*/check = CheckURL(url);
		/*if (row.empty())
		 return NULL;*/
		if (check)
		{
			//url->populate(row);
			//url->show = show;
			//if (url->enabled > 0)
			return url;
		}
	}
	return NULL;
}

// Самая весёлая функция.
//	 Поиск доступных ссылок производится не чаще, чем раз в 5 минут, для
// снижения нагрузки на сервер
//	 Исключение: если первая из ссылок, которую надо бы сейчас посетить
// оказывается отключенной, то производится внеплановый перепоиск.
mysqlpp::Row AppSurfing::GetTaskListURLs()
{
	char today[80];
	strftime(today, 80, "%Y-%m-%d", timeinfo);

	int proxy = 0;
	mysqlpp::Row row;
	if ((TaskURLs->size() == 0))
	{
		mysqlpp::Query query = con->query();
		// Что выбираем -- только информацию о самой ссылке
		query << "SELECT tasks_mem.* FROM tasks_mem "
				<< "LEFT JOIN placetarget_ci ON (placetarget_ci.placetargetid=tasks_mem.placetargetid AND placetarget_ci.target = "
				<< user.user_location << ") "
				<< "LEFT JOIN taskcacheuser ON (taskcacheuser.linkid=tasks_mem.linkid AND taskcacheuser.userid="
				<< user.userid << " AND taskcacheuser.day=" << mysqlpp::quote
				<< today << ") "
				<< "LEFT JOIN taskcacheuserlastday ON (taskcacheuserlastday.userid="
				<< user.userid
				<< " AND taskcacheuserlastday.linkid=tasks_mem.linkid) "
				<< "LEFT JOIN taskcacheip ON (taskcacheip.linkid=tasks_mem.linkid AND taskcacheip.ip="
				<< user.remoteAddr << " AND taskcacheip.day=" << mysqlpp::quote
				<< today << ") "
				<< "LEFT JOIN tasks_block ON (tasks_block.linkid=tasks_mem.linkid AND tasks_block.userid="
				<< user.userid << ") " << "WHERE (enabled=1) AND ";
		// блокировка публичных прокси
		if (proxy == 1)
			query << " (allowproxy=1) AND ";
		// Поддержка блокировки ссылки самим юзером
		query << "(tasks_block.description IS NULL) AND "
		// скрывать ссылку от самого себя
				<< "(tasks_mem.userid<>" << user.userid << " OR hide=0) AND "

		// Фильтрация по параметрам самой ссылки
				// В случае taskid=1: вип серфинг, учитываются все ограничения
				// В случае taskid=2: стандарт серфинг, лимита по юзеру нет, только ip
				// В случае taskid=3: лайт серфинг, учитывается все
				// В случае taskid=4: хит серфинг, ограничения на число посещений человеком нет
				<< "((" << user.showcat << " & (1 << tasks_mem.code))<>0) AND "
				<< "((taskcacheuserlastday.day is null) OR DATEDIFF(CURRENT_TIMESTAMP, taskcacheuserlastday.day) >= tasks_mem.intervalshowuser) AND "
				<< "((maxshowday = 0) OR "
				<< "(!tasks_mem.reginterval AND maxshowday > taskcacheday_visits) OR (maxshowday*"
				<< beginday << " > taskcacheday_visits)) AND "
				<< "((tasks_mem.code=4) OR (tasks_mem.code=2) OR (taskcacheuser.visits is null) OR (maxshowuser > taskcacheuser.visits)) AND "
				<< "((tasks_mem.code=4) OR (taskcacheip.visits is null) OR (maxshowuser > taskcacheip.visits)) AND "
		// Таймтаргеттинг
				<< "((timelimit_timelimitid IS NULL) OR ("
				<< "(day_visits IS NULL) AND (hour_visits IS NULL) AND "
				<< "((timelimit_visits=0) OR "
				<< "(timelimit_visits > taskcachehour_visits AND (!tasks_mem.reginterval OR (timelimit_visits*"
				<< beginhour << ") > taskcachehour_visits)) )"

		<< " OR ((day_visits IS NOT NULL) AND (hour_visits IS NULL) AND "
				<< "(day_visits=0 OR "
				<< "(day_visits > taskcacheday_visits AND (!tasks_mem.reginterval OR (day_visits*"
				<< beginday << " > taskcacheday_visits)))) ) "

		<< " OR ((hour_visits is not null) and " << "(hour_visits=0 OR "
				<< "(hour_visits > taskcachehour_visits AND (!tasks_mem.reginterval OR (hour_visits*"
				<< beginhour << ") > taskcachehour_visits)))) )) AND "

		// Местотаргеттинг
				<< "((!tasks_mem.placetargetid) OR (placetarget_ci.target = "
				<< user.user_location << ") ) AND (1=1)";



		mysqlpp::UseQueryResult res = query.use();

		while (row = res.fetch_row())
		{
			int userid = atoi(row["userid"].c_str());
			int linkid = atoi(row["linkid"].c_str());
			int balance = atoi(row["balance"].c_str());
			int time_limit = (strcmp(row["timelimit_visits"].c_str(), "NULL")
					== 0) ? -RAND_MAX : atoi(row["timelimit_visits"].c_str());
			int
					maxshowday = (strcmp(row["maxshowday"].c_str(), "NULL")
							== 0) ? -RAND_MAX : atoi(row["maxshowday"].c_str());
			int
					day_visits =
							/*(strcmp(row["taskcacheday_visits"].c_str(), "NULL"))?-RAND_MAX:*/atoi(
									row["taskcacheday_visits"].c_str());
			int
					day_limit =
							(strcmp(row["day_visits"].c_str(), "NULL") == 0) ? -RAND_MAX
									: atoi(row["day_visits"].c_str());
			int
					hour_limit = (strcmp(row["hour_visits"].c_str(), "NULL")
							== 0) ? -RAND_MAX
							: atoi(row["hour_visits"].c_str());

			DEBUG("%d CheckTaskURLs TEST url: %d time_limit %s maxshowday %s day_limit %s hour_limit %s",
					user.userid, linkid, row["timelimit_visits"].c_str(), row["maxshowday"].c_str(), row["day_visits"].c_str(), row["hour_visits"].c_str());
			//int tasktype = atoi(row["tasktype"].c_str());
			if ((userid != 67027 || user.refucur > 2) && (userid != 470836
					|| user.refucur > 5))
			{
				Url * url = new Url();
				url->populate(row);
				//DEBUG("%d GetTaskListURLs fulllist url: %d", user.userid, url->linkid);
				TaskURLs->push_back(url);
			}
			CheckUrl *churl = check_find(CheckTaskURLs, linkid);
			if (!churl)
			{
				churl = new CheckUrl();
				churl->linkid = linkid;
				churl->balance = balance;
				churl->time_limit = (time_limit == 0) ? RAND_MAX : time_limit;
				churl->maxshowday = (maxshowday == 0) ? RAND_MAX : maxshowday;
				churl->day_visits = day_visits;
				churl->day_limit = (day_limit == 0) ? RAND_MAX : day_limit;
				churl->hour_limit = (hour_limit == 0) ? RAND_MAX : hour_limit;
				churl->hour = timeinfo->tm_hour;
				churl->day = timeinfo->tm_mday;
				CheckTaskURLs->push_back(churl);

				DEBUG("%d CheckTaskURLs ADD url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
						user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
			}
			else
			{
				churl->balance = balance;
				churl->time_limit = (time_limit == 0) ? RAND_MAX : time_limit;
				churl->maxshowday = (maxshowday == 0) ? RAND_MAX : maxshowday;
				churl->day_limit = (day_limit == 0) ? RAND_MAX : day_limit;
				churl->hour_limit = (hour_limit == 0) ? RAND_MAX : hour_limit;
			}
		}

		DEBUG("%d GetTaskListURLs fulllist size %d", user.userid, TaskURLs->size());

		if (TaskURLs->size() > 1)
			sort(TaskURLs->begin(), TaskURLs->end(), taskscmp);
	}
	//	SAFE_FREE(today);
	return row;
}

/*mysqlpp::Row*/bool AppSurfing::CheckTaskURL(Url * url)
{

	DEBUG("%d CheckTaskURLs SIZE %d", user.userid, CheckTaskURLs->size());
	//  $now = getdate($curts);
	//  $today = sprintf('%04d-%02d-%02d', $now['year'], $now['mon'], $now['mday']);

	/*char buffer[80];

	 strftime(buffer, 80, "%Y-%m-%d", timeinfo);
	 mysqlpp::UseQueryResult res;
	 DEBUG("%d CheckTaskURL: %d", user.userid, url->linkid);*/
	if (url)
	{
		// При проверке возвращаем одну ссылку
		int idx = 0;
		CheckUrl *churl = NULL;
		for (checkiter element = CheckTaskURLs->begin(); element
				< CheckTaskURLs->end(); element++)
		{
			churl = (*element);
			if ((churl) && (churl->linkid == url->linkid))
			{
				//mysqlpp::Query query = con->query();
				//mysqlpp::SimpleResult res;
				if ((churl->balance <= 0) || ((churl->time_limit != -RAND_MAX)
						&& (churl->time_limit <= churl->count))
						|| ((churl->maxshowday != -RAND_MAX)
								&& (churl->maxshowday <= churl->day_visits))
						|| ((churl->day_limit != -RAND_MAX)
								&& (churl->day_limit <= churl->day_visits))
						|| ((churl->hour_limit != -RAND_MAX)
								&& (churl->hour_limit <= churl->count))
						|| (churl->day != timeinfo->tm_mday) || (churl->hour
						!= timeinfo->tm_hour))
				{
					/*query << "UPDATE taskcacheday " << "SET visits = visits + " << churl->day_count << ", "
					 //<< "visits_uniq = visits_uniq + " << uniq << " "
					 << "WHERE linkid=" << churl->linkid << " AND " << "day="
					 << mysqlpp::quote << today; //TODO: не today а из churl
					 res = query.execute();
					 if (res.rows() == 0)
					 {
					 query
					 << "INSERT INTO taskcacheday(linkid, day, visits, visits_uniq) "
					 << "VALUES (" << churl->linkid << "," << mysqlpp::quote
					 << today << "," << churl->day_count << uniq << ")"; //TODO: не today а из churl
					 res = query.execute();
					 }
					 else
					 DEBUG("%d ShowTaskURL taskcacheday updated %d", user.userid,
					 res.rows());

					 // 4. taskcachehour (linkid, day, hour, visits)
					 //mysqlpp::Query query = con->query();
					 query << "UPDATE taskcachehour SET visits = visits + " << churl->hour_count
					 << "WHERE linkid=" << churl->linkid << " AND " << "hour="
					 << churl->hour << " AND " << "day=" << mysqlpp::quote
					 << today; //TODO: не today а из churl
					 res = query.execute();
					 if (res.rows() == 0)
					 {
					 //mysqlpp::Query query = con->query();
					 query
					 << "INSERT INTO taskcachehour(linkid, hour, day, visits) "
					 << "VALUES (" << churl->linkid << ","
					 << churl->hour << "," << mysqlpp::quote << today
					 << "," << churl->hour_count << ")"; //TODO: не today а из churl
					 res = query.execute();
					 }
					 else
					 DEBUG("%d ShowTaskURL taskcachehour updated %d", user.userid, res.rows());*/

					DEBUG("%d CheckTaskURLs REMOVED url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
							user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);

					SAFE_DELETE(CheckTaskURLs->at(idx));
					CheckTaskURLs->erase(CheckTaskURLs->begin() + idx);
					return false;
				}
				if ((churl) && (churl->balance > 0))
				{
					if (churl->maxshowday != -RAND_MAX)
					{
						if (url->reginterval == 0)
						{
							if (churl->maxshowday > churl->day_visits)
							{

								DEBUG("%d CheckTaskURLs MAXSHOWDAY url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
						else
						{
							if ((churl->maxshowday * beginday)
									> churl->day_visits)
							{

								DEBUG("%d CheckTaskURLs MAXSHOWDAY REG url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
					}
					else if (churl->hour_limit != -RAND_MAX)
					{
						if (url->reginterval == 0)
						{
							if (churl->hour_limit > churl->count)
							{

								DEBUG("%d CheckTaskURLs HOUR url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
						else
						{
							if ((churl->hour_limit * beginhour) > churl->count)
							{

								DEBUG("%d CheckTaskURLs HOUR REG url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
					}
					else if (churl->day_limit != -RAND_MAX)
					{
						if (url->reginterval == 0)
						{
							if (churl->day_limit > churl->day_visits)
							{

								DEBUG("%d CheckTaskURLs DAY url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
						else
						{
							if ((churl->day_limit * beginday)
									> churl->day_visits)
							{

								DEBUG("%d CheckTaskURLs DAY REG url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
										user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
								return true;
							}
						}
					}
					else if (churl->time_limit != -RAND_MAX)
					{
						if (churl->time_limit > churl->count)
						{

							DEBUG("%d CheckTaskURLs TIMELIMIT url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
									user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
							return true;
						}
					}
					else
					{

						DEBUG("%d CheckTaskURLs BALANCE url: %d balance %d time_limit %d maxshowday %d day_limit %d hour_limit %d count %d uniq %d",
								user.userid, churl->linkid, churl->balance, churl->time_limit, churl->maxshowday, churl->day_limit, churl->hour_limit, churl->count, churl->uniq);
						return true;
					}
				}
				break;
			}
			idx++;
		}
	}

	DEBUG("%d CheckTaskURLs FALSE FOR %d", user.userid, url->linkid);
	return /*res.fetch_row(); */false;
}

void AppSurfing::PartnerEarn(int category, int partnerid, double sum)
{
	// Получает партнер ...
	// Если category>1, то это рекламодатель партнера
	if (category > 1)
	{
		DEBUG("%d PartnerEarn sum %f", partnerid, sum);
		ChangeBalance(39, sum, partnerid, false);
	}
		else
		DEBUG("%d PartnerEarn NO sum %f", partnerid, sum);

	/*	mysqlpp::Query query = con->query();
	 query << "SELECT categories.category, categories.userid as partnerid FROM `categories` "
	 << "LEFT JOIN user ON user.category=categories.category "
	 << "WHERE user.userid=" << userid;

	 mysqlpp::StoreQueryResult res = query.store();
	 if ((res) && (res.num_rows() == 1))
	 {
	 mysqlpp::Row row = res.at(0);

	 // Получает партнер ...
	 // Если category>1, то это рекламодатель партнера
	 if(atoi(row["category"])>1)
	 {

	 DEBUG("%d PartnerEarn sum %f", userid, sum);
	 ChangeBalance(39, sum, atoi(row["partnerid"]));
	 } else
	 DEBUG("%d PartnerEarn NO sum %f", userid, sum);
	 } else
	 DEBUG("%d PartnerEarn NO2 sum %f", userid, sum);*/
}

/* Рекламодатель потратил N$
 Данная функция производит рассчет новых скидок, возможно возвращая часть
 суммы с ссылок и рассылок на счет рекламодателя.

 Аргументы: ID рекламодателя, потраченная сумма.
 Возвращает факт успешности.
 */
double AppSurfing::AdvertPay(int userid, double sum, int part_category,
		int partnerid) // &$getref
{
	getadvref = 0;

	DEBUG("%d AdvertPay sum %f", user.userid, sum);
	/*
	 // Необходима блокировка таблиц: при возможном прерасчете чтобы
	 // точно за время другой поток тоже не начал перерасчет
	 //sql_begin($db);*/
	mysqlpp::Query query = con->query();
	query
			<< "SELECT user.discount as discount,user.disneed as disneed,user.discur as discur,user.disnew as disnew,"
			<< "auth.refid as refid,refuser.refaperc as refrefaperc,user.category as category "
			<< "FROM user LEFT JOIN auth ON auth.userid=user.userid "
			<< "LEFT JOIN user as refuser ON (refuser.userid=auth.refid) "
			<< "WHERE auth.userid=" << userid << " FOR UPDATE";
	mysqlpp::StoreQueryResult res = query.store();
	if ((res) && (res.num_rows() == 1))
	{
		mysqlpp::Row row = res.at(0);
		mysqlpp::Row nextval;
		mysqlpp::Row newval;
		mysqlpp::Row vv;
		discount = atof(row["discount"].c_str());
		sum *= 1 - discount;
		double refrefaperc = 0;
		int refid = atoi(row["refid"].c_str());
		std::string upsql;// = "";
		double balchange = 0;
		double discur = atof(row["discur"].c_str());
		double disneed = atof(row["disneed"].c_str());
		double rd = atof(row["discount"].c_str());
		char * category = strdup(row["category"].c_str());

		DEBUG("%d AdvertPay 1 sum %f", user.userid, sum);
		if (!row["refrefaperc"].is_null())
			refrefaperc = atof(row["refrefaperc"].c_str());
		//		res.purge();
		// 1е: проверим, не потребуется ли изменение скидки
		if (discur + sum >= disneed)
		{

			DEBUG("%d AdvertPay NEW DISCOUNT ", user.userid);
			// требуется...
			query << "SELECT * FROM discounts WHERE category=" << category
					<< " AND amount>" << (discur + sum)
					<< " ORDER BY amount ASC LIMIT 1";
			res = query.store();
			if ((res) && (res.num_rows() == 1)) // есть еще куда расти
			{
				nextval = res.at(0);
				//				res.purge();
			}
				else
				DEBUG("%d AdvertPay1 NO RES: %s", user.userid, query.error());

			query << "SELECT * FROM discounts WHERE category=" << category
					<< " AND amount<=" << (discur + sum)
					<< " ORDER BY amount DESC LIMIT 1";
			res = query.store();
			if ((res) && (res.num_rows() == 1)) // собсно, выросли
			{
				newval = res.at(0);
				//				res.purge();
			}
				else
				DEBUG("%d AdvertPay2 NO RES: %s", user.userid, query.error());

			if (newval)
			{ // Найдем новую скидку

				DEBUG("%d AdvertPay 3 ", user.userid);
				upsql += ",discount=";
				upsql += newval["discount"].c_str();
				double nd = atof(newval["discount"].c_str());
				// 1е: посчитаем скидку на ссылках
				query << "SELECT sum(balance*priceadv)/1000 as s FROM links "
						<< "WHERE userid=" << userid
						<< " AND balance>0 AND costtype=1";
				res = query.store();
				vv = res.at(0);
				//				res.purge();

				// 1.1: учтем возврат
				balchange += atof(vv["s"].c_str()) * (nd - rd);

				// 2е: посчитаем скидку на емылах
				query
						<< "SELECT sum((sendcnt-come)*price)/1000 as s FROM emailing "
						<< "WHERE userid=" << userid << " AND templateid=4 "
						<< "AND `when`>=CURRENT_TIMESTAMP-INTERVAL length DAY";
				res = query.store();
				vv = res.at(0);
				//				res.purge();

				// 2.1: учтем возврат
				balchange += atof(vv["s"].c_str()) * (nd - rd);

				// 3е: посчитаем скидку на регистрациях
				query
						<< "SELECT sum(balance*priceadv)/1000 as s FROM registers "
						<< "WHERE userid=" << userid
						<< " AND balance>0 AND costtype=1";
				res = query.store();
				vv = res.at(0);
				//				res.purge();

				// 3.1: учтем возврат
				balchange += atof(vv["s"].c_str()) * (nd - rd);

				// 4е: посчитаем скидку на заданиях
				query << "SELECT sum(balance*priceadv)/1000 as s FROM tasks "
						<< "WHERE userid=" << userid
						<< " AND balance>0 AND costtype=1";
				res = query.store();
				vv = res.at(0);
				//				res.purge();

				// 4.1: учтем возврат
				balchange += atof(vv["s"].c_str()) * (nd - rd);
			}

			if (nextval)
			{ // Есть куда расти

				DEBUG("%d AdvertPay 4 ", user.userid);
				upsql += ",disneed=";
				upsql += nextval["amount"].c_str();
				upsql += ",disnew=";
				upsql += nextval["discount"].c_str();
			}
			else
			{

				DEBUG("%d AdvertPay 5 ", user.userid);
				upsql += ",disneed=0,disnew=0";
			}
		}
			else
			DEBUG("%d AdvertPay NO NEW DISCUR discur + sum >= disneed: %f %f", user.userid,
					(discur + sum), disneed);

		query << "UPDATE user SET discur=discur+" << sum << upsql
				<< " WHERE userid=" << userid;
		mysqlpp::SimpleResult ires = query.execute();
		if (ires.rows() == 0)
		{

			DEBUG("%d AdvertPay ACHTUNG NO NEW DISCUR %f", user.userid,
					(discur + sum));
		}
			else
			DEBUG("%d AdvertPay: %d  NEW DISCUR = %f", user.userid, userid, (discur + sum));

		//		res.purge();
		// есть что вернуть...int rd = atoi(row["discount"].c_str());
		if (balchange)
		{

			DEBUG("%d AdvertPay RETURN BALANCE: %f", user.userid, balchange);
			ChangeBalance(14, balchange, userid, false);
		}

		DEBUG("ACHTUNG ADVERPAY %d %d %f %f", refid, userid, refrefaperc, sum);
		// Последнее: зачислим рефералу
		if ((refid && refrefaperc && sum) && (refid != partnerid))
		{
			getadvref = refrefaperc * sum;

			DEBUG("ADVERPAY getadvref: %f", getadvref);
			ChangeBalance(13, getadvref, refid, false);
		}
		// Если category>1, то это рекламодатель партнера.
		// Считаем доход VipIP
		if (part_category > 1)
		{
			getvipip = sum * VIPIP_EARN;
		}
		if (refrefaperc * sum)
		{
			// И саааамое последнее -- зафиксируем в refpercents факт прибыли
			query << "UPDATE refpercents SET aperc = aperc + " << (refrefaperc
					* sum) << " WHERE userid=" << refid << " AND userref="
					<< userid;
			//		res.purge();
			ires = query.execute();
			if ((ires) && (ires.rows() == 0))
			{
				query
						<< "INSERT INTO refpercents(userid, userref, aperc) VALUES "
						<< "(" << refid << "," << userid << "," << (refrefaperc
						* sum) << ")";
				query.execute();
			}
				else
				DEBUG("%d AdvertPay3 NO RES: %s", user.userid, query.error());
		}
		SAFE_FREE(category);
	}
		else
		DEBUG("%d AdvertPay4 NO RES: %s", user.userid, query.error());
	//sql_commit($db);
	return getadvref;
}

// Если force установлено, то балансу при изменении будет позволено уйти в минус
bool AppSurfing::ChangeBalance(int op, double amount, int userid = 0,
		bool force = false)
{

	DEBUG("%d AppSurfing::ChangeBalance %d, %f, %d", user.userid, op,
			amount, userid);

	mysqlpp::Query query = con->query();
	mysqlpp::SimpleResult ires;
	if (amount != 0)
	{
		//if (!userid) userid = $_SESSION['user']['userid'];

		query << "UPDATE user SET balance=balance+(" << amount
				<< ") WHERE userid=" << userid;
		// Так как точность, с которой баланс показан пользователю -- 6 знаков, то
		// баланс -0.00000049 для него тоже ноль. Поэтому при проверке допускаем погрешность в 7м знаке
		if (amount < 0 && !force)
			query << " AND balance>=" << (-amount - 0.0000005);

		ires = query.execute();
		if (ires && ires.rows() != 1)
		{
			// Баланс недостаточный, обламываем
			// Так как мы еще ничего не сделали -- то и откатывать нечего

			DEBUG("%d Баланс недостаточный, обламываем", user.userid);
			return false;
		}
			else
			DEBUG("%d ChangeBalance1 NO RES: %s", user.userid, query.error());

		char when[80];
		/*int curts = */
		strftime(when, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
		//char * when = strdup(buffer);
		char today[80];
		strftime(today, 80, "%Y-%m-%d", timeinfo);
		//char * today = strdup(buffer);

		query
				<< "INSERT INTO balance_log_buf(userid,balop,amount,`when`) VALUES "
					"(" << userid << "," << op << "," << amount << ","
				<< mysqlpp::quote << when << ")";

		ires = query.execute();
		if (!ires)
		{

			DEBUG("%d Какие-то проблемы с записью лога", user.userid);
			// Какие-то проблемы с записью лога?
			// Откатим баланс взад и вернём ошибку
			query << "UPDATE user SET balance=balance-(" << amount
					<< ") WHERE userid=" << userid;
			query.execute();
			//			SAFE_FREE(today);
			//			SAFE_FREE(when);
			return false;
		}

		//	  $sql = "INSERT INTO balance_log(userid,balop,amount,`when`) VALUES ".
		//			 "(".$userid.",".$op.",".$amount.",".$when.")";
		//	  $res = sql_query($db, $sql);

		if (op == 2)
		{ // вывод средств
			query << "UPDATE money_stat SET user_get=user_get+" << fabs(amount);
			query.execute();

			query << "UPDATE money_daily_stat SET user_get=user_get+" << fabs(
					amount) << " WHERE day=" << mysqlpp::quote << today;
			ires = query.execute();
			if (ires && (ires.rows() == 0))
			{
				query
						<< "INSERT INTO money_daily_stat (day, user_earn, user_get) "
						<< "VALUES (" << mysqlpp::quote << today << ",0,"
						<< fabs(amount) << ")";
				query.execute();
			}
		}
		else if (op == 18)
		{ // возврат при неудачном выводе
			query << "UPDATE money_stat SET user_get=user_get-" << fabs(amount);
			query.execute();
			query << "UPDATE money_daily_stat SET user_get=user_get-" << fabs(
					amount) << " WHERE day=" << mysqlpp::quote << today;
			query.execute();
		}
		else if (op == 19)
		{ //изменение суммы пользователя партнером системы
			query
					<< "INSERT INTO partner_transfer_log (partnerid, userid, amount, `when`) "
					<< "VALUES (" << user.userid << "," << userid << ","
					<< amount << ", " << mysqlpp::quote << when << ")";
			query.execute();
		}
		else if (op == 3 || //продажа акций
				op == 5 || //доход со страниц
				op == 11 || //доход с заработка реферала
				op == 12 || //доход с писем
				op == 13 || //доход с работодателея
				op == 16 || //доход с лотереи
				op == 21 || //Доход от регистраций
				op == 23 //доход от выполнения заданий
		)
		{

			DEBUG("%d Пишем money_daily_stat", user.userid);
			query << "UPDATE money_stat SET user_earn=user_earn+" << amount;
			query.execute();
			query << "UPDATE money_daily_stat SET user_earn=user_earn+"
					<< fabs(amount) << " WHERE day=" << mysqlpp::quote << today;
			ires = query.execute();
			if (ires && (ires.rows() == 0))
			{

				DEBUG("%d Какие-то проблемы с записью money_daily_stat", user.userid);
				query
						<< "INSERT INTO money_daily_stat (day, user_earn, user_get) "
						<< "VALUES (" << mysqlpp::quote << today << ","
						<< fabs(amount) << ",0)";
				query.execute();
			}
		}
		//		SAFE_FREE(today);
		//		SAFE_FREE(when);
		return true; // Всё ОК
	}
	return true; // Изменение на ноль - удачно
}

/* Юзер заработал N$
 Данная функция производит рассчет новых процентов заработка как следствие
 заработка юзером некой суммы.

 Аргументы: ID юзера, заработанная сумма.
 Возвращает факт успешности.
 */
double AppSurfing::UserEarn(int userid, double sum, int vfor, int category,
		int partnerid) //&$getref
{
	double getref = 0;

	DEBUG("%d AppSurfing::UserEarn(%d) %f",user.userid, userid, sum);
	mysqlpp::Query query = con->query();
	query << "SELECT user.refucur,user.refuneed,user.refunew,user.category, "
			<< "auth.refid, refuser.refuperc as refrefuperc, refuser.refucur as refrefucur, "
			<< "refuser.category as refcategory FROM user "
			<< "LEFT JOIN auth ON auth.userid = user.userid "
			<< "LEFT JOIN user as refuser ON (refuser.userid=auth.refid)"
			<< "WHERE auth.userid=" << userid;

	mysqlpp::StoreQueryResult res = query.store();
	if (res && (res.num_rows() == 1))
	{
		mysqlpp::Row row = res.at(0);
		double refrefuperc = atof(row["refrefuperc"].c_str());
		int refid = atoi(row["refid"].c_str());
		double refucur = atof(row["refucur"].c_str());
		int refuneed = atoi(row["refuneed"].c_str());

		DEBUG("%d AppSurfing2::UserEarn(%d) %f",user.userid, userid, sum);

		//		res.purge();
		// Получает сам юзер ...
		ChangeBalance(vfor, sum, userid, false);

		DEBUG("%d UserEarn user: %d", user.userid, userid);
		// Получает его реферал


		/* Получает его реферал */
		if (category != atoi(row["refcategory"]))
		{
			refrefuperc = 0;
			/* Находим реф. процент рефа по категории рекламодателя */
			query << "SELECT * FROM refupercents WHERE category=" << category
					<< " AND amount<=" << row["refrefucur"]
					<< " ORDER BY amount DESC LIMIT 1";
			mysqlpp::StoreQueryResult res = query.store();
			if (res && (res.num_rows() == 1))
			{
				mysqlpp::Row row = res.at(0);
				refrefuperc = atof(row["refuperc"].c_str());
			}
		}

		/* рефу зачисляем только в том случае, если реф это не сам партнер */
		if (refid && (refid != partnerid))
		{
			getref = sum * refrefuperc;
			ChangeBalance(11, getref, refid);
		}
		// Проверим теперь не поднялся ли процент...
		std::string upsql;
		if (refucur + sum >= refuneed)
		{

			DEBUG("%d UserEarn NEW DISCOUNT: %d", user.userid, userid);
			mysqlpp::Row nextval;
			mysqlpp::Row newval;
			// поднялся...
			query << "SELECT * FROM refupercents WHERE category="
					<< row["category"] << " AND amount>" << (refucur + sum)
					<< " ORDER BY amount ASC LIMIT 1";
			res = query.store();

			// есть еще куда расти
			if (res && (res.num_rows() == 1))
			{
				nextval = res.at(0);
				//				res.purge();
			}

			query << "SELECT * FROM refupercents WHERE category="
					<< row["category"] << " AND amount<=" << (refucur + sum)
					<< " ORDER BY amount DESC LIMIT 1";
			res = query.store();
			// собсно, выросли
			if (res && (res.num_rows() == 1))
			{
				newval = res.at(0);
				//				res.purge();
			}

			if (newval)
			{ // Найдем новую скидку
				upsql += ",refuperc=";
				upsql += newval["refuperc"].c_str();
			}
			if (nextval)
			{ // Есть куда расти
				upsql += ",refuneed=";
				upsql += nextval["amount"].c_str();
				upsql += ",refunew=";
				upsql += nextval["refuperc"].c_str();
			}
			else
			{
				upsql += ",refuneed=0,refunew=0";
			}
		}
			else
			DEBUG("%d UserEarn NO NEW REFUCUR refucur + sum >= refuneed: %f %d", user.userid,
					(refucur + sum), refuneed);

		query << "UPDATE user SET refucur=refucur+" << sum << upsql
				<< " WHERE userid=" << userid;

		mysqlpp::SimpleResult ires = query.execute();
		if (ires.rows() == 0)
		{

			DEBUG("%d UserEarn ACHTUNG NO NEW REFUCUR", user.userid);
		}
			else
			DEBUG("%d UserEarn: %d NEW refucur = %f", user.userid, userid, (refucur + sum));
		if (refrefuperc)
		{
			// И саааамое последнее -- зафиксируем в refpercents факт прибыли
			query << "UPDATE refpercents " << "SET uperc = uperc + " << (sum
					* refrefuperc) << " WHERE userid=" << refid
					<< " AND userref=" << userid;

			mysqlpp::SimpleResult ires = query.execute();
			if (ires && (ires.rows() == 0))
			{
				query
						<< "INSERT INTO refpercents(userid, userref, uperc) VALUES "
						<< "(" << refid << "," << userid << "," << (sum
						* refrefuperc) << ")";
				query.execute();
			}
		}
	}
		else
		DEBUG("%d UserEarn NO RES: %s", user.userid, query.error());
	return getref;
}

/*
 Считаем заработок сервиса
 $amount - сумма
 $earnop - тип серфинга, регистрации или задания(VIP, STD и т.д.).
 $balop - заработок, трата или реф процент
 */
void AppSurfing::ServiceEarn(double amount, int earnop, int balop)
{

	DEBUG("%d AppSurfing::ServiceEarn %f %d %d", user.userid, amount,
			earnop, balop);
	if (amount > 0)
	{
		mysqlpp::Query query = con->query();
		query << "UPDATE visitcacheserviceearn SET amount=amount+" << amount
				<< " WHERE day=DATE(NOW()) AND earnop=" << earnop
				<< " AND balop=" << balop;

		mysqlpp::SimpleResult res = query.execute();
		if (res && (res.rows() == 0))
		{
			try
			{

				DEBUG("%d AppSurfing::ServiceEarn2 %d %s", user.userid,
						res.rows(), res.info());
				query
						<< "INSERT INTO visitcacheserviceearn (day, amount, earnop, balop) "
						<< "VALUES (DATE(NOW())," << amount << "," << earnop
						<< "," << balop << ")";
				query.execute();
			} catch (const mysqlpp::BadQuery& er)
			{
				// Handle any query errors

				DEBUG("%d ACHTUNG ServiceEarn Query error: %s %s", user.userid,
						query.str().c_str(), er.what());
			}
		}
	}
		else
		DEBUG("%d ServiceEarn ACHTUNG amount=0", user.userid);
}
//   Определение местонахождения текущего юзера.
//   Возвращает ID для сравнения с placetarget_ci
void AppSurfing::LocateUser()
{
	mysqlpp::Query query = con->query();
	query << "SELECT CityID FROM ip2c_network WHERE beginip<="
			<< user.remoteAddr << " AND " << "endip>=" << user.remoteAddr
			<< " ORDER BY length LIMIT 1";

	mysqlpp::StoreQueryResult res = query.store();
	if (res && (res.num_rows() == 1))
	{
		mysqlpp::Row row = res.at(0);
		user.user_location = atoi(row["CityID"].c_str());
		//		res.purge();
	}
	else
		user.user_location = 0;
}

void AppSurfing::AfterUserEarn(int userid, int surfid, int costtype,
		double priceuser, double priceadv, int paid, double getuserref,
		int category, int partnerid)
{
	getadvref = getvipip = 0;
	double _priceuser = priceuser * paid / 1000.0;
	ServiceEarn(_priceuser, surfid, 32);
	if (getuserref)
		ServiceEarn(getuserref, surfid, 33);
	double _priceadv = priceadv / 1000.0;
	if (costtype == 1)
	{
		// Рекламодатель реально потратил... (рефералу уплочено)
		getadvref = AdvertPay(userid, _priceadv, category, partnerid);

		ServiceEarn(_priceadv * (1 - discount), surfid, 30);
		if (getadvref)
			ServiceEarn(getadvref, surfid, 31);
		if (getvipip)
			ServiceEarn(getvipip, surfid, 38);
	}
		else
		DEBUG("%d COSTTYPE != 1", user.userid);
	// Зачисляем партнеру

	DEBUG("%d AfterUserEarn sum _priceadv: %f, discount: %f, getadvref: %f, priceuser: %f, getuserref: %f, getvipip: %f ", userid, _priceadv, discount, getadvref, _priceuser, getuserref, getvipip );
	PartnerEarn(category, partnerid, _priceadv * (1 - discount) - getadvref
			- _priceuser - getuserref - getvipip);
}

//   Ссылка просмотрена и пользователь ответил на формочку.
//   Запоминается момент просмотра, факт просмотра, факт оплаченности и
//   начисляются (если нужно) пользователю денежки.
//   Ссылка из URLs'ов на этом убивается
bool AppSurfing::UrlTaskViewed(Url * url, int succ, int paid, int app)
{
	if (url && (url->show != 0) && ((now - url->show) >= url->timer))
	{
		mysqlpp::Query query = con->query();
		query << "UPDATE tasks_log " << "SET success=" << (succ ? 1 : 0) << ","
				<< "paid=" << (succ ? paid : 0) << " " << "WHERE linkslogid="
				<< url->logid;
		mysqlpp::SimpleResult ires = query.execute();
		if (ires)
		{

			DEBUG("%d AppSurfing::UrlTaskViewed have res %d", user.userid, ires.rows());
			if (paid && succ)
			{

				DEBUG("%d AppSurfing::UrlTaskViewed paid && succ", user.userid);
				// Заплатим юзеру
				double getref = UserEarn(user.userid, url->priceuser * paid
						/ 1000.0, 23, url->category, url->partnerid);
				AfterUserEarn(url->userid, 6, url->costtype, url->priceuser,
						url->priceadv, paid, getref, url->category,
						url->partnerid);
			}
				else
				DEBUG("%d AppSurfing::UrlTaskViewed NO paid or succ", user.userid);
			return true;
		}
			else
			DEBUG("%d UrlTaskViewed1 NO RES: %s", user.userid, query.error());
	}
		else
		DEBUG("%d !!! AppSurfing::UrlTaskViewed NO url or url->show!=0 RES: %d", user.userid,
				(url ? url->show : -1));

	return false;
}

//   Ссылка просмотрена и пользователь ответил на формочку.
//   Запоминается момент просмотра, факт просмотра, факт оплаченности и
//   начисляются (если нужно) пользователю денежки.
//   Ссылка из URLs'ов на этом убивается
//   $advcheck=1 - серфим без фрейма

bool AppSurfing::UrlViewed(Url * url, int succ, int paid, int app, int autoapp)
{
	if (url && (url->show != 0) && ((now - url->show) >= url->timer))
	{
		mysqlpp::Query query = con->query();
		query << "UPDATE links_log SET success=" << (succ ? 1 : 0) << ","
				<< "paid=" << (succ ? paid : 0) << " WHERE linkslogid="
				<< url->logid;
		mysqlpp::SimpleResult ires = query.execute();
		if (ires)
		{

			DEBUG("%d AppSurfing::UrlViewed have res %d", user.userid, ires.rows());
			if (paid && succ)
			{

				DEBUG("%d AppSurfing::UrlViewed paid && succ", user.userid);
				// Заплатим юзеру
				float getref = UserEarn(user.userid, url->priceuser * paid
						/ 1000.0, 5, url->category, url->partnerid);
				AfterUserEarn(url->userid, url->surfid, url->costtype,
						url->priceuser, url->priceadv, paid, getref,
						url->category, url->partnerid);
			}
			return true;
		}
			else
			DEBUG("%d UrlViewed1 NO RES: %s", user.userid, query.error());
	}
		else
		DEBUG("%d !!! AppSurfing::UrlViewed NO url or url->show!=0 RES: %d %d %d", user.userid,
				url->linkid, (url ? url->show : -1), linkid);
	return false;
}
