//============================================================================
// Name        : vipipd.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include <crypto++/cryptlib.h>
#include <crypto++/md5.h>
#include <crypto++/hex.h>
#include <iostream>
#include <string>
#include <fstream>

#include "AppSurfing.h"
#include "Session.h"

// Глобальное
debugLevel_t fs_debugLevel = DL_DEBUG;
#define SURFING_TTL 1200
#define PATH_TO_IMAGES "../../public_html/imgdyn/surfimage/"

std::map<std::string, AppSurfing*> surfing;
std::map<std::string, AppSurfing*>::iterator surf_itr;
checkvector * CheckURLs = 0;
checkvector * CheckTaskURLs = 0;
struct evhttp* httpd;

class MyConnectionPool : public mysqlpp::ConnectionPool {
public:
    // The object's only constructor

    MyConnectionPool(const char* db, const char* server, const char* user,
            const char* password) :
    db_(db ? db : ""), server_(server ? server : ""),
    user_(user ? user : ""), password_(password ? password : "") {
    }

    // The destructor.  We _must_ call ConnectionPool::clear() here,
    // because our superclass can't do it for us.

    ~MyConnectionPool() {
        clear();
    }

protected:
    // Superclass overrides

    mysqlpp::Connection* create() {
        // Create connection using the parameters we were passed upon
        // creation.  This could be something much more complex, but for
        // the purposes of the example, this suffices.
        DEBUG("Create connection"); // indicate connection creation
        return new mysqlpp::Connection(db_.empty() ? 0 : db_.c_str(),
                server_.empty() ? 0 : server_.c_str(),
                user_.empty() ? 0 : user_.c_str(),
                password_.empty() ? "" : password_.c_str());
    }

    void destroy(mysqlpp::Connection* cp) {
        // Our superclass can't know how we created the Connection, so
        // it delegates destruction to us, to be safe.
        DEBUG("Destroy connection"); // indicate connection destruction
        SAFE_DELETE(cp);
    }

    unsigned int max_idle_time() {
        // Set our idle time at an example-friendly 3 seconds.  A real
        // pool would return some fraction of the server's connection
        // idle timeout instead.
        return 60;
    }

private:
    // Our connection parameters
    std::string db_, server_, user_, password_;
};
MyConnectionPool* poolptr = 0;

class Image {
public:
    const char* fn;
    int w, x;

    Image(const char* fn, int w, int x) {
        this->fn = strdup(fn);
        this->w = w;
        this->x = x;
    }

    ~Image() {
        SAFE_DELETE(fn);
    }
};
Image * images[5000];
Image * advimages[5000];

/**
 * Checks if supplied parameter is a valid host value. Valid host values
 * should be in the form: "xmpp:" ihost [ ":" port ]
 *
 * NOTE: RFC 3987 defines the form of ihost like this: ihost = IP-literal /
 * IPv4address / ireg-name This function cuts corners and uses
 * InetAddress.getByName() to check ihost validity.
 *
 *
 * @see java.net.InetAddress
 * @param route
 *            hostname that should be checked
 * @return 'true' if host is in the form "xmpp:" ihost [ ":" port ]
 *         otherwise 'false'.
 */
bool isValidRoute(std::string route) {
    if (route.substr(0, strlen("xmpp:")).compare("xmpp:") != 0) {
        return false;
    }

    route = route.substr(strlen("xmpp:"));

    // check for port validity, if a port is given.
    unsigned int port = route.rfind(":", std::string::npos);
    if (port != std::string::npos) {
        int p = atoi(route.substr(port + 1).c_str());
        if (p < 0 || p > 65535) {
            return false;
        }
        route = route.substr(0, port);
    }

    //	InetAddress.getByName(route);
    return true;
}

//
// Берет `uri` и удаляет аргументы запроса.
//

char* parse_path(const char* uri) {
    char c;
    int i, j;
    char* ret = (char*) malloc(strlen(uri) + 1);
    for (i = j = 0; uri[i] != '\0'; i++) {
        c = uri[i];

        if (c == '?') {
            break;
        } else {
            ret[j++] = c;
        }
    }
    ret[j] = '\0';
    return ret;
}

//
// Проверить находится ли path в memcached, если нет
// то соединение разрывается без ответа
// и тогда nginx перенаправит запрос
//

void print_headers(const struct evkeyvalq *headers) {
    struct evkeyval *header;

    TAILQ_FOREACH(header, headers, next) {
        DEBUG("Query Param: %s -> %s", header->key, header->value);
    }
}

void replace_all(std::string & in, const std::string & plain,
        const std::string & tok) {
    /*string::size_type*/int n = 0;
    const std::string::size_type l = plain.length();
    while (1) {
        n = in.find(plain, n);
        if (n != -1)
            in.replace(n, l, tok);
        else
            break;
    }
}

void parse_query(const char *uri, struct evkeyvalq *headers) {
    char Buff[2049];
    memset(Buff, '\0', 2049);
    char * p = &Buff[0];

    TAILQ_INIT(headers);

    if (strlen(uri) < 2048)
        strcpy(p, uri);
    else
        FATAL("ACHTUNG SIZE > 2048 %s", uri);

    while (p != NULL && *p != '\0') {
        char *value = strsep(&p, "&");
        if (value) {
            char *key = strsep(&value, "=");
            if (value) {
                value = evhttp_decode_uri(value);

                std::string stval(value);
                //stval.replace(stval.find("\r\n"), strlen("\r\n"), "<br/>");
                //string stval("asgjhg\r\nsjh\r\ngjhg");
                replace_all(stval, "\r\n", "<br/>");
                /*replace(stval.begin(), stval.end(), '\r', ' ');
                 replace(stval.begin(), stval.end(), '\n', ' ');*/
                evhttp_add_header(headers, key, stval.c_str());
                DEBUG("key: %s value %s", key, stval.c_str());
            } else
                DEBUG("ACHTUNG URI %s", key);
        } else
            goto error;
        SAFE_FREE(value);
    }

error:
    return;
}

void parse_coockie(const char *uri, struct evkeyvalq *headers) {
    char Buff[2049];
    memset(Buff, '\0', 2049);
    char * p = &Buff[0];

    TAILQ_INIT(headers);

    if (strlen(uri) < 2048)
        strcpy(p, uri);
    else
        FATAL("ACHTUNG SIZE > 2048 %s", uri);

    while (p != NULL && *p != '\0') {
        char *value = NULL;
        char *argument = strsep(&p, ";");
        if (argument[0] == ' ')
            argument++;

        value = argument;
        char *key = strsep(&value, "=");
        if (value == NULL)
            goto error;

        value = evhttp_decode_uri(value);
        evhttp_add_header(headers, key, value);
        SAFE_FREE(value);
    }

error:
    return;
}

UConverter *utf8conv = NULL;
UConverter *cp1251conv = NULL;
UErrorCode status = U_ZERO_ERROR;

char* utf8_to_cp1251(const char *source) {
    int source_len = strlen(source);
    uint32_t len, len2;

    UChar *uBuf;
    uBuf = (UChar*) malloc((source_len) * sizeof (UChar) * 2);
    len = ucnv_toUChars(utf8conv, uBuf, source_len * 2, source, source_len,
            &status);
    U_ASSERT(status);

    char *bytes = (char*) malloc(source_len * sizeof (char) + 1);
    memset(bytes, 0, source_len * sizeof (char));
    len2 = ucnv_fromUChars(cp1251conv, bytes, source_len, uBuf, len, &status);
    //	DEBUG("%d len %d %d", source_len, len, len2);
    U_ASSERT(status);
    bytes[len2] = '\0';
    SAFE_FREE(uBuf);
    return bytes;
}

char* cp1251_to_utf8(const char *source) {
    int source_len = strlen(source);
    uint32_t len, len2;

    UChar *uBuf;
    uBuf = (UChar*) malloc((source_len) * sizeof (UChar) * 2);
    len = ucnv_toUChars(cp1251conv, uBuf, source_len * 2, source, source_len,
            &status);
    U_ASSERT(status);

    char *bytes = (char*) malloc(source_len * sizeof (char) * 2 + 1);
    memset(bytes, 0, source_len * sizeof (char) * 2);
    len2 = ucnv_fromUChars(utf8conv, bytes, source_len * 2, uBuf, len, &status);
    DEBUG("%d %d %d", source_len, len, len2);
    U_ASSERT(status);
    bytes[len2] = '\0';

    SAFE_FREE(uBuf);
    return bytes;
}

void parseStory(xmlDocPtr doc, xmlNodePtr cur) {

    xmlChar *key;
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *) "keyword"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            printf("keyword: %s\n", key);
            xmlFree(key);
        }
        cur = cur->next;
    }
    return;
}

bool running = true;

void memcache_handler(struct evhttp_request* req, void* arg) {
    if (!running)
        exit(0);

    struct evbuffer* buf = evbuffer_new();

    if (buf == NULL)
        err(1, "failed to create response buffer");

    char* request_uri = parse_path(req->uri);

    // Проверка на переполнение буфера
    if (strlen(request_uri) > 125)
        evhttp_connection_free(req->evcon);
    else {
        if (req->type == EVHTTP_REQ_POST)
            DEBUG("req: %s POST", req->uri);
        else
            DEBUG("req: %s NO POST", req->uri);

        //print_headers(req->input_headers);
        const char * Cookie = evhttp_find_header(req->input_headers, "Cookie");
        struct evkeyvalq coockies;
        TAILQ_INIT(&coockies);
        const char *session_id = NULL;
        int trackip = 0;

        char getBuff[2049];
        memset(getBuff, '\0', 2049);
        char * pGetBuff = &getBuff[0];
        if (strlen(req->uri) < 2048)
            strcpy(pGetBuff, req->uri);
        else
            FATAL("ACHTUNG SIZE > 2048 %s", req->uri);
        strsep(&pGetBuff, "?");
        char *params = strsep(&pGetBuff, "?");

        if ((Cookie != NULL) && (strlen(Cookie) > 0)) {
            const char *track_ip = NULL;
            DEBUG("Cookie: %s", Cookie);
            std::string cookie = Cookie;
            /*string key = "PHPSESSID";
             size_t found = cookie.rfind(key);
             //if (found !=0) DEBUG("%s", cookie.substr(found).c_str());
             if (found != string::npos)
             parse_coockie(cookie.substr(found).c_str(), &coockies);
             else*/
            parse_coockie(cookie.c_str(), &coockies);
            //print_headers(&coockies);
            session_id = evhttp_find_header(&coockies, "PHPSESSID");
            track_ip = evhttp_find_header(&coockies, "trackip");
            if (track_ip)
                trackip = htonl(inet_addr(track_ip));
        }
        //        else
        //            DEBUG("Coockie is NULL");

        struct evkeyvalq getquery;
        TAILQ_INIT(&getquery);
        if (params)
            parse_query(params, &getquery);
        //        DEBUG("AFTER PARSE params %s", params);
        //		SAFE_FREE(getbuff);
        if (!session_id) //пробуем найти sid в запросе
            session_id = evhttp_find_header(&getquery, "sid");
        //memcached_return rc = MEMCACHED_SUCCESS;

        struct evkeyvalq headers;
        TAILQ_INIT(&headers);

        if (EVBUFFER_LENGTH(req->input_buffer)) {
            char * p = (char*) EVBUFFER_DATA(req->input_buffer);
            *(p + EVBUFFER_LENGTH(req->input_buffer)) = '\0';
            parse_query(p, &headers);

            AppSurfing * surf = NULL;
            char * respbuf = NULL;
            // req->remote_host используется в случае
            // прямого коннекта к сервису
            // мы же устанавливаем заголовок ReamoteAddr с помощью nginx
            // и здесь его получаем :)
            const char * remote;
            if (evhttp_find_header(req->input_headers, "RemoteAddr"))
                remote = evhttp_find_header(req->input_headers, "RemoteAddr");
            else
                remote = req->remote_host;
            //const char * remote = evhttp_find_header(req->input_headers, "RemoteAddr");
            //const char * remote = req->remote_host;
            // Если нет идентификатора сессии и запрос идет на логин
            if (strcmp(req->uri, "/http-bind/") == 0) {
                //DEBUG("getting query %s", remote);
                char * p = (char*) EVBUFFER_DATA(req->input_buffer);
                *(p + EVBUFFER_LENGTH(req->input_buffer)) = '\0';
                DEBUG("post data %s", p);
                xmlDocPtr doc; /* the resulting document tree */

                /*
                 * The document being in memory, it have no base per RFC 2396,
                 * and the "noname.xml" argument will serve as its base.
                 */
                doc = xmlReadMemory(p, strlen(p), "noname.xml", NULL, 0);
                if (doc == NULL) {
                    DEBUG("Failed to parse document\n");
                    //return;
                } else {
                    xmlNodePtr cur = xmlDocGetRootElement(doc);

                    if (cur == NULL) {
                        DEBUG("empty document\n");
                        xmlFreeDoc(doc);
                        return;
                    }

                    if (xmlStrcmp(cur->name, (const xmlChar *) "body")) {
                        DEBUG("document of the wrong type, root node != body");
                        evhttp_send_reply(req, HTTP_BADREQUEST, "OK", buf);
                    } else {
                        DEBUG("here [%s]", cur->name);
                        //			xmlChar *uri = xmlGetProp(cur, (xmlChar *) "to");
                        //
                        //			printf("to: %s\n", uri);
                        //			xmlFree(uri);
                        //
                        //			//cur = cur->xmlChildrenNode;
                        //			while (cur != NULL) {
                        ////		if ((!xmlStrcmp(cur->name, (const xmlChar *)"body"))){
                        //parseStory(doc, cur);
                        ////		}
                        //cur = cur->next;
                        //			}


                        // we got a <body /> request - let's look if there something useful we could do with it
                        xmlChar *xmlSid = xmlGetProp(cur, (xmlChar *) "sid");
                        if (xmlSid != NULL) {
                            DEBUG("has sid");
                            // lookup existing session ***
                            Session * sess = Session::getSession((char*) xmlSid);

                            if (sess != NULL) {
                                DEBUG("incoming request for %s", sess->getSID().c_str());
                                // check if request is valid check if rid valid
                                xmlChar *xmlRid = xmlGetProp(cur, (xmlChar *) "rid");
                                if (xmlRid == NULL) {
                                    // rid missing
                                    DEBUG("rid missing");
                                    evhttp_send_reply(req, HTTP_NOTFOUND, "OK", buf);
                                    sess->terminate();
                                } else {
                                    int rid = atoi((char*) xmlRid);
                                    Response * r = sess->getResponse(rid);
                                    if (r != NULL) { // resend
                                        DEBUG("resend rid %ld", rid);
                                        r->setAborted(true);
                                        r->send(req, buf);
                                        //			return;
                                    } else {
                                        if (!sess->checkValidRID(rid)) {
                                            DEBUG("invalid rid %ld", rid);
                                            evhttp_send_reply(req, HTTP_NOTFOUND, "OK", buf);
                                            sess->terminate();
                                        } else {
                                            DEBUG("found valid rid %ld", rid);

                                            // too many simultaneous requests?
                                            if (sess->numPendingRequests() >= Session::MAX_REQUESTS) {
                                                DEBUG("too many simultaneous requests: %d", sess->numPendingRequests());
                                                evhttp_send_reply(req, HTTP_BADREQUEST, "OK", buf); // FORBIDDEN
                                                // no pardon - kick it
                                                sess->terminate();
                                            } else {
                                                // у нас есть валидный запрос начинаем обрабатывать его
                                                Response *jresp = new Response();
                                                jresp->setRID(rid);
                                                jresp->setContentType(sess->getContent());
                                                sess->addResponse(jresp);

                                                /*
                                                 * NOTE: This only works when having
                                                 * MAX_REQUESTS set to 1 or 2 Otherwise we would
                                                 * fail on the condition that incoming data from
                                                 * the client has to be forwarded as soon as
                                                 * possible (the request might be pending
                                                 * waiting for others to timeout first)
                                                 * wait 'till we are the lowest rid that's
                                                 * pending
                                                 */

                                                long lastrid = sess->getLastDoneRID() + 1;
                                                DEBUG("%ld waiting for %ld", rid, lastrid);
                                                if (rid != lastrid) {
                                                    //while (rid != lastrid) {
                                                    if (sess->isStatus(Session::SESS_TERM)) {
                                                        DEBUG("session terminated for %ld", rid);
                                                        evhttp_send_reply(req, HTTP_NOTFOUND, "OK", buf);
                                                        //	sess.sock.notifyAll();
                                                        //	return;
                                                    }
                                                    DEBUG("%ld waiting for %ld", rid, lastrid);
                                                    //	sess.sock.wait();
                                                    lastrid = sess->getLastDoneRID() + 1;
                                                }

                                                DEBUG("handling response %ld", rid);
                                                // check key
                                                std::string key = sess->getKey();
                                                if (key != NULL) {
                                                    DEBUG("checking keys for %ld", rid);
                                                    xmlChar *xmlKey = xmlGetProp(cur, (xmlChar *) "key");
                                                    if (xmlKey == NULL /*|| !sha1((char*)xmlKey).equals(key)*/) {
                                                        DEBUG("Key sequence error");
                                                        evhttp_send_reply(req, HTTP_NOTFOUND, "OK", buf);
                                                        sess->terminate();
                                                        //	return;
                                                    }
                                                    xmlChar *xmlNewKey = xmlGetProp(cur,
                                                            (xmlChar *) "newkey");
                                                    if (xmlNewKey != NULL)
                                                        sess->setKey((char*) xmlNewKey);
                                                    else
                                                        sess->setKey((char*) xmlKey);
                                                    DEBUG("key valid for %d", rid);
                                                }

                                                xmlChar *xmlRestart = xmlGetProp(cur,
                                                        (xmlChar *) "restart");
                                                DEBUG("HANDLING RESTART [%s]", xmlRestart);
                                                if (xmlRestart != NULL) {
                                                    DEBUG("XMPP RESTART");
                                                    sess->setReinit(true);
                                                    jresp->setAttribute("xmlns:stream", "http://etherx.jabber.org/streams");
//                                                    xmlNodePtr streamFeatures = xmlNewNode(NULL, BAD_CAST "stream:features");
//
//                                                    xmlNodePtr compression = xmlNewNode(NULL, BAD_CAST "compression");
//                                                    xmlSetProp(compression, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/features/compress");
//                                                    xmlAddChild(streamFeatures, compression);
//                                                    xmlNodePtr method = xmlNewNode(NULL, BAD_CAST "method");
//                                                    xmlAddChild(compression, method);
//                                                    xmlNodeSetContent(method, BAD_CAST "zlib");
//                                                    xmlNodePtr bind = xmlNewNode(NULL, BAD_CAST "bind");
//                                                    xmlSetProp(bind, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-bind");
//                                                    xmlAddChild(streamFeatures, bind);
//                                                    xmlNodePtr session = xmlNewNode(NULL, BAD_CAST "session");
//                                                    xmlSetProp(session, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-session");
//                                                    xmlAddChild(streamFeatures, session);
//
//                                                    jresp->addNode(streamFeatures, "asd");
                                                } else
                                                    DEBUG(" NO RESTART HANDLING RESTART [%s]", cur->name);

                                                // check if we got sth to forward to remote jabber server
                                                xmlNodePtr rootNode = xmlDocGetRootElement(doc);
                                                if (rootNode)
                                                    sess->sendNodes(rootNode);
                                                else {
                                                    // check if polling too frequently only empty polls are considered harmfull
                                                    long now = time(NULL);
                                                    if (sess->getHold() == 0 && now - sess->getLastPoll() < Session::MIN_POLLING * 1000) {
                                                        // indeed (s)he's violating our rules
                                                        DEBUG("polling too frequently! [now: %d, last: %d (%d)]", now,
                                                                sess->getLastPoll(), (now - sess->getLastPoll()));

                                                        //	response.sendError(HttpServletResponse.SC_FORBIDDEN);
                                                        // no pardon - kick it
                                                        sess->terminate();
                                                        //	return;
                                                    }
                                                    // mark last empty poll
                                                    sess->setLastPoll();
                                                }

                                                // send response
                                                // request to terminate session?
                                                xmlChar *xmlType = xmlGetProp(cur,
                                                        (xmlChar *) "type");
                                                if (xmlType != NULL) {
                                                    if (strcmp((char*) xmlType, "terminate") == 0) {
                                                        sess->terminate();
                                                        jresp->send(req, buf);
                                                        //	return;
                                                    }
                                                }

                                                // check incoming queue
                                                xmlNodePtr nl = sess->checkInQ(rid);
                                                // add items to response
                                                if (nl != NULL) {
                                                    DEBUG("NODELIST NOT EMPTY [%s]", nl->name);
                                                    xmlChar *key;
                                                    nl = nl->xmlChildrenNode;
                                                    while (nl != NULL) {
                                                        if (xmlStrcmp(nl->name, (const xmlChar *) "starttls") != 0) {
                                                            jresp->addNode(nl, "asdf");
                                                            //                                                    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                                                            //                                                    printf("keyword: %s\n", key);
                                                            //                                                    xmlFree(key);
                                                            DEBUG("keyword: %s\n", nl->name);
                                                        }
                                                        nl = nl->next;
                                                    }
                                                } else DEBUG("NODELIST IS EMPTY");

                                                if (sess->streamFeatures) {
                                                    jresp->setAttribute("xmlns:stream", "http://etherx.jabber.org/streams");
                                                    sess->streamFeatures = false; // reset
                                                }

                                                /* check for streamid (digest auth!) */
                                                if (!sess->authidSent && sess->getAuthid() != NULL) {
                                                    sess->authidSent = true;
                                                    jresp->setAttribute("authid", sess->getAuthid());
                                                }

                                                if (sess->isStatus(Session::SESS_TERM)) {
                                                    // closed due to stream error
                                                    jresp->setAttribute("type", "terminate");
                                                    jresp->setAttribute("condition", "remote-stream-error");
                                                }

                                                /* finally send back response */
                                                jresp->send(req, buf);
                                                sess->setLastDoneRID(jresp->getRID());
                                                //			sess.sock.notifyAll();
                                                //		}
                                                //	} catch (IOException ioe) {
                                                DEBUG("HERE 8");
                                                //                                                sess->terminate();
                                                //                                                jresp->setAttribute("type", "terminate");
                                                //                                                jresp->setAttribute("condition", "remote-connection-failed");
                                                //                                                jresp->send(req, buf);
                                                //	}
                                            }
                                        }
                                    }
                                }
                            } else {
                                // session not found!
                                evhttp_send_reply(req, HTTP_NOTFOUND, "OK", buf);
                            }
                        } else {
                            DEBUG("no sid");

                            // request to create a new session ***
                            long rid = 0;
                            xmlChar *xmlRid =
                                    xmlGetProp(cur, (xmlChar *) "rid");
                            if (xmlRid == NULL) {
                                evhttp_send_reply(req, HTTP_BADREQUEST, "OK", buf);
                            } else {
                                rid = atol((char*) xmlRid);
                                DEBUG("has rid %d", rid);

                                Response * jresp = new Response(/*db.newDocument(),request*/);
                                jresp->setRID(rid);

                                // check 'route' attribute
                                xmlChar *xmlRoute = xmlGetProp(cur, (xmlChar *) "route");
                                std::string route;
                                if ((xmlRoute != NULL) && isValidRoute(
                                        std::string((char*) xmlRoute))) {
                                    route = std::string((char*) xmlRoute).substr(
                                            strlen("xmpp:"));
                                }

                                // check 'to' attribute
                                xmlChar *xmlTo = xmlGetProp(cur, (xmlChar *) "to");
                                std::string to;
                                if ((xmlTo != NULL) && (strcmp((char*) xmlTo, "") != 0)) {
                                    to = std::string((char*) xmlTo);
                                    // really create new session
                                    try {
                                        DEBUG("HERE 0");
                                        Session * sess = new Session(to, route);
                                        sess->start();
                                        DEBUG("HERE 1");
                                        xmlChar *xmlContent = xmlGetProp(cur, (xmlChar *) "content");
                                        if (xmlContent != NULL)
                                            sess->setContent((char*) xmlContent);
                                        xmlChar *xmlWait = xmlGetProp(cur, (xmlChar *) "wait");
                                        if (xmlWait != NULL)
                                            sess->setWait(atoi((char*) xmlWait));
                                        xmlChar *xmlHold = xmlGetProp(cur, (xmlChar *) "hold");
                                        if (xmlHold != NULL)
                                            sess->setHold(atoi((char*) xmlHold));
                                        xmlChar *xmlLand = xmlGetProp(cur, (xmlChar *) "xml:lang");
                                        if (xmlLand != NULL)
                                            sess->setXMLLang((char*) xmlLand);
                                        xmlChar *xmlNewKey = xmlGetProp(cur, (xmlChar *) "newkey");
                                        if (xmlNewKey != NULL)
                                            sess->setKey((char*) xmlNewKey);
                                        xmlChar *xmlSecure = xmlGetProp(cur, (xmlChar *) "secure");
                                        if (xmlSecure != NULL && (strcmp(
                                                (char*) xmlSecure, "true") == 0
                                                || strcmp((char*) xmlSecure, "1") == 0))
                                            sess->setSecure(true); // forces IOException

                                        sess->addResponse(jresp);
                                        DEBUG("HERE 2");

                                        // send back response
                                        jresp->setContentType(sess->getContent());

                                        /* check incoming queue */
                                        xmlNodePtr nl = sess->checkInQ(jresp->getRID());

                                        // add items to response
                                        if (nl != NULL) {
                                            DEBUG("NODELIST NOT EMPTY [%s]", nl->name);
                                            xmlChar *key;
                                            nl = nl->xmlChildrenNode;
                                            while (nl != NULL) {
                                                if (xmlStrcmp(nl->name, (const xmlChar *) "features") == 0) {
                                                    DEBUG("keyword1: %s\n", nl->name);
                                                    //xmlNodePtr features = xmlNewNode(NULL, BAD_CAST "stream:features");

                                                    xmlNodePtr mechanisms = xmlNewNode(NULL, BAD_CAST "mechanisms");
                                                    xmlSetProp(mechanisms, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-sasl");
                                                    xmlAddChild(nl, mechanisms);

                                                    xmlNodePtr jive = xmlNewNode(NULL, BAD_CAST "mechanism");
                                                    xmlAddChild(mechanisms, jive);
                                                    xmlNodeSetContent(jive, BAD_CAST "JIVE-SHAREDSECRET");

                                                    xmlNodePtr plain = xmlNewNode(NULL, BAD_CAST "mechanism");
                                                    xmlAddChild(mechanisms, plain);
                                                    xmlNodeSetContent(plain, BAD_CAST "PLAIN");

                                                    xmlNodePtr anonymous = xmlNewNode(NULL, BAD_CAST "mechanism");
                                                    xmlAddChild(mechanisms, anonymous);
                                                    xmlNodeSetContent(anonymous, BAD_CAST "ANONYMOUS");

                                                    xmlNodePtr crammd5 = xmlNewNode(NULL, BAD_CAST "mechanism");
                                                    xmlAddChild(mechanisms, crammd5);
                                                    xmlNodeSetContent(crammd5, BAD_CAST "CRAM-MD5");

                                                    xmlNodePtr compression = xmlNewNode(NULL, BAD_CAST "compression");
                                                    xmlSetProp(compression, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/features/compress");
                                                    xmlAddChild(nl, compression);
                                                    xmlNodePtr method = xmlNewNode(NULL, BAD_CAST "method");
                                                    xmlAddChild(compression, method);
                                                    xmlNodeSetContent(method, BAD_CAST "zlib");
                                                    xmlNodePtr bind = xmlNewNode(NULL, BAD_CAST "bind");
                                                    xmlSetProp(bind, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-bind");
                                                    xmlAddChild(nl, bind);
                                                    xmlNodePtr session = xmlNewNode(NULL, BAD_CAST "session");
                                                    xmlSetProp(session, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-session");
                                                    xmlAddChild(nl, session);
                                                    jresp->addNode(nl, "asdf");
                                                } else
                                                    if (xmlStrcmp(nl->name, (const xmlChar *) "starttls") != 0) {
                                                    jresp->addNode(nl, "asdf");
                                                    //                                                    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                                                    //                                                    printf("keyword: %s\n", key);
                                                    //                                                    xmlFree(key);
                                                    DEBUG("keyword: %s\n", nl->name);
                                                    //                                                    xmlNodePtr newNode = xmlNewNode(NULL, BAD_CAST ns.c_str());
                                                    //                                                    xmlAddChild(this->body, n);
                                                }
                                                nl = nl->next;
                                            }
                                        } else DEBUG("NODELIST IS EMPTY");
                                        if (sess->streamFeatures) {
                                            jresp->setAttribute("xmlns:stream", "http://etherx.jabber.org/streams");
                                            sess->streamFeatures = false; // reset
                                        }

                                        DEBUG("HERE 3");
                                        if (sess->getAuthid() != NULL) {
                                            sess->authidSent = true;
                                            jresp->setAttribute("authid", sess->getAuthid());
                                        }

                                        jresp->setAttribute("sid", sess->getSID());
                                        jresp->setAttribute("secure", "true");
                                        jresp->setAttribute("requests", Session::MAX_REQUESTS);
                                        jresp->setAttribute("inactivity", Session::MAX_INACTIVITY);
                                        jresp->setAttribute("polling", Session::MIN_POLLING);
                                        jresp->setAttribute("wait", sess->getWait());
                                        jresp->setAttribute("hold", 1);
                                        jresp->setAttribute("ack", 3444873137);
                                        jresp->setAttribute("maxpause", 300);
                                        jresp->setAttribute("ver", "1.6");

                                        if (sess->isStatus(Session::SESS_TERM))
                                            jresp->setAttribute("type", "terminate");
                                        jresp->send(req, buf);
                                        sess->setLastDoneRID(jresp->getRID());
                                        DEBUG("HERE 4");
                                    } catch (std::exception uhe) {
                                        // ERROR: remote host unknown
                                        DEBUG("EXCEPTION");
                                        xmlChar *xmlContent = xmlGetProp(cur, (xmlChar *) "content");
                                        if (xmlContent != NULL) {
                                            jresp->setContentType((char*) xmlContent);
                                        } else {
                                            jresp->setContentType(Session::DEFAULT_CONTENT);
                                        }

                                        jresp->setAttribute("type", "terminate");
                                        jresp->setAttribute("condition", "host-unknown");
                                        jresp->send(req, buf);
                                        //} catch (IOException ioe) {

                                        // ERROR: could not connect to remote host
                                        xmlContent = xmlGetProp(cur,
                                                (xmlChar *) "content");
                                        if (xmlContent != NULL)
                                            jresp->setContentType((char*) xmlContent);
                                        else
                                            jresp->setContentType(Session::DEFAULT_CONTENT);
                                        jresp->setAttribute("type", "terminate");
                                        jresp->setAttribute("condition", "remote-connection-failed");
                                        jresp->send(req, buf);
                                        //} catch (NumberFormatException nfe) {
                                        evhttp_send_reply(req, HTTP_BADREQUEST, "OK", buf);
                                        //	return;
                                    }
                                } else {
                                    // ERROR: 'to' attribute missing or emtpy
                                    xmlChar *xmlContent = xmlGetProp(cur,
                                            (xmlChar *) "content");
                                    if (xmlContent != NULL)
                                        jresp->setContentType((char*) xmlContent);
                                    else
                                        jresp->setContentType(Session::DEFAULT_CONTENT);

                                    jresp->setAttribute("type", "terminate");
                                    jresp->setAttribute("condition", "improper-addressing");
                                    jresp->send(req, buf);
                                    //	return;
                                }
                            }
                        }
                        //////////////////////////////////////////////////////////////////////////////
                    }
                }
                xmlFreeDoc(doc);

                xmlCleanupParser();
            } else
                DEBUG("No coockie");
            evhttp_send_reply(req, HTTP_OK, "OK", buf);
            //evhttp_connection_free(req->evcon);
        } else {
            DEBUG("no post data IS GET");
            if (strcmp(req->uri, "/crossdomain.xml") == 0) {
                //Выбираем случайнуюю картинку
                std::string fname = "crossdomain.xml";
                // Открываем дескриптор файла,
                int fd = open(fname.c_str(), O_RDONLY);
                evhttp_add_header(req->output_headers, "Content-Type", Session::DEFAULT_CONTENT);
                // Читаем длину файла
                int fSize = lseek(fd, 0, SEEK_END);
                lseek(fd, 0, SEEK_SET);
                // И функцией evbuffer_read загоняем его в вывод
                evbuffer_read(buf, fd, fSize);
                close(fd);
                DEBUG("GETTING CROSSDOMAIN %s size %d", fname.c_str(), fSize);
            }
            evhttp_send_reply(req, HTTP_OK, "OK", buf);
        }
        evhttp_clear_headers(&headers);
        evhttp_clear_headers(&coockies);
    }
    //evhttp_clear_headers(req->input_headers);
    SAFE_FREE(request_uri);
    evbuffer_free(buf);
}

struct sigaction act_open;

void atExit1(void) {
    printf("Exiting...\n");
    DEBUG_DONE();
    if (cp1251conv)
        ucnv_close(cp1251conv);
    cp1251conv = NULL;
    if (utf8conv)
        ucnv_close(utf8conv);
    utf8conv = NULL;
    std::map<std::string, AppSurfing*>::iterator element;
    for (element = surfing.begin(); element != surfing.end(); element++) {
        AppSurfing *t = (*element).second;
        SAFE_DELETE(t);
    }
    surfing.clear();
    //SAFE_DELETE_ARRAY(advimages);
    //SAFE_DELETE_ARRAY(images);
    if (httpd)
        evhttp_free(httpd);
}

void sigHandler_SIGINT(int signal) {
    atExit1();
    // Set SIGINT back to the default action
    act_open.sa_handler = SIG_DFL;
    sigaction(SIGINT, &act_open, 0);
    running = false;
    kill(getpid(), SIGINT);
}

void sigHandlerInstall() {
    act_open.sa_flags = 0;
    // Create a mostly open mask -- only masking SIGINT
    sigemptyset(&act_open.sa_mask);
    sigaddset(&act_open.sa_mask, SIGINT);
    act_open.sa_handler = sigHandler_SIGINT;
    sigaction(SIGINT, &act_open, 0);
}

int check(std::string keybuf) {
    CryptoPP::MD5 hash;
    byte digest[CryptoPP::MD5::DIGESTSIZE];
    hash.CalculateDigest(digest, (byte*) keybuf.c_str(), keybuf.length());

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof (digest));
    encoder.MessageEnd();
    transform(output.begin(), output.end(), output.begin(), ::tolower);
    DEBUG("%s", output.c_str());
    return 1;
}

int SERVICE_PORT = 0;

int main(int argc, char** argv) {
    utf8conv = ucnv_open("utf-8", &status);
    U_ASSERT(status);
    cp1251conv = ucnv_open("windows-1251", &status);
    U_ASSERT(status);
    atexit(atExit1);
    sigHandlerInstall();
    event_init();
    time_t rawtime;
    int now = time(&rawtime);
    struct tm * timeinfo = localtime(&rawtime);
    int lnow = mktime(timeinfo);
    DEBUG_INIT(fs_debugLevel, "./log/server.log", app_version);
    DEBUG("%d %d %d", now, now + timeinfo->tm_gmtoff, lnow);
    // тест
    //	{
    //		string keybuf = app_version;
    //		keybuf.append("-1592638884592cfd2b3c8cba307f6deb-");
    //		string sess = "da46ea264a17a37cc1444030015fe8fb";
    //		//keybuf.append(sess.substr(0, 20));
    //		//sess.push_back(sess.at(0));
    //		//sess.erase(0,1);
    //		keybuf.append(sess.c_str());
    //		DEBUG("%s", keybuf.c_str());
    //		check(keybuf);
    //	}
    //	{
    //		string keybuf = app_version;
    //		keybuf.append("-1592638884592cfd2b3c8cba307f6deb-");
    //		string sess = "da46ea264a17a37cc1444030015fe8fb";
    //		//keybuf.append(sess.substr(0, 20));
    //		//sess.push_back(sess.at(0));
    //		//sess.erase(0,1);
    //		keybuf.append(sess);
    //		DEBUG("%s", keybuf.c_str());
    //		check(keybuf);
    //	}
    // тест

    if (argv[2] != NULL)
        SERVICE_PORT = atoi(argv[2]);
    else
        std::cerr << "Set the pot in command line" << std::endl;

    httpd = evhttp_start(argv[1], atoi(argv[2]));
    if (httpd) {
        poolptr = new MyConnectionPool(DB_DATABASE, DB_HOST, DB_USER,
                DB_PASSWORD);
        try {
            mysqlpp::Connection* cp = poolptr->grab();
            if (!cp->thread_aware()) {
                std::cerr << "MySQL++ wasn't built with thread awareness!  "
                        << argv[0] << " can't run without it." << std::endl;
                return 1;
            }
            //Готовим мем таблицу
            /*mysqlpp::Query query = cp->query();
             query << "select count(*) as count from surfimage_mem";
             mysqlpp::StoreQueryResult res = query.store();
             mysqlpp::Row row = res.at(0);
             int memimages = atoi(row["count"].c_str());
             if ( memimages == 0 ) // Если не заполнена то заполняем
             {
             DEBUG("FILING surfimage_mem");
             query << "insert into surfimage_mem (id, fn, x, y, w, h) select id, fn, x, y, w, h from surfimage_test";
             mysqlpp::SimpleResult ires = query.execute();
             if (ires && (ires.rows() != 0)) memimages = ires.rows();
             } else
             DEBUG("ALREADY FILLED surfimage_mem");*/

            {
                mysqlpp::Query query = cp->query();
                query << "SELECT * FROM surfimage_test WHERE advside=0";
                mysqlpp::UseQueryResult res = query.use();
                int counter = 0;
                while (mysqlpp::Row row = res.fetch_row()) {
                    images[counter] = new Image(row["fn"].c_str(),
                            atoi(row["w"].c_str()), atoi(row["x"].c_str()));
                    counter++;
                    if (counter == 5000)
                        break;
                }
            }
            {
                mysqlpp::Query query = cp->query();
                query << "SELECT * FROM surfimage_test WHERE advside=1";
                mysqlpp::UseQueryResult res = query.use();
                int counter = 0;
                while (mysqlpp::Row row = res.fetch_row()) {
                    advimages[counter] = new Image(row["fn"].c_str(),
                            atoi(row["w"].c_str()), atoi(row["x"].c_str()));
                    counter++;
                    if (counter == 5000)
                        break;
                }
            }

            poolptr->release(cp);
        } catch (mysqlpp::Exception& e) {
            DEBUG("Failed to set up initial pooled connection: %s", e.what());
            return 1;
        }
        CheckURLs = new checkvector;
        CheckTaskURLs = new checkvector;
        srand(time(NULL));
        evhttp_set_gencb(httpd, memcache_handler, NULL);
        event_dispatch();
    }
    return 0;
}

//
//private static final long serialVersionUID = 1L;
//
//public static final String APP_VERSION = "1.1.1";
//
//public static final String APP_NAME = "Jabber HTTP Binding Servlet";
//
//public static final bool DEBUG = true;
//
//public static final int DEBUG_LEVEL = 4;
//
//private DocumentBuilder db;
//
//private Janitor janitor;
//
//private static JHBServlet srv;
//
//public void init() throws ServletException {
//	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
//	try {
//		db = dbf.newDocumentBuilder();
//	} catch (ParserConfigurationException e) {
//		log("failed to create DocumentBuilderFactory", e);
//	}
//
//	janitor = new Janitor(); // cleans up sessions
//	new Thread(janitor).start();
//	srv = this;
//}
//
//public void destroy() {
//	Session.stopSessions();
//	janitor.stop();
//}
//
//public static String hex(byte[] array) {
//	StringBuffer sb = new StringBuffer();
//	for (int i = 0; i < array.length; ++i) {
//		sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100)
//.toLowerCase().substring(1, 3));
//	}
//	return sb.toString();
//}
//
//public static String sha1(String message) {
//	try {
//		MessageDigest sha = MessageDigest.getInstance("SHA-1");
//		return hex(sha.digest(message.getBytes()));
//	} catch (NoSuchAlgorithmException e) {
//	}
//	return NULL;
//}

