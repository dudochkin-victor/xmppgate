/*
 * Response.h
 *
 *  Created on: 01.02.2011
 *      Author: blacksmith
 */

#ifndef RESPONSE_H_
#define RESPONSE_H_

#include "debug.h"
#include <iostream>
#include <sys/queue.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include "unicode/utypes.h"   /* Basic ICU data types */
#include "unicode/ucnv.h"     /* C   Converter API    */
#include "unicode/ustring.h"  /* some more string fcns*/
#include "unicode/uchar.h"    /* char names           */
#include "unicode/uloc.h"
#include "unicode/unistr.h"
#include <netinet/in.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <map>
#include <sstream>
#include <string>
#include <algorithm>
#include <event.h>
#include <evhttp.h>
#include <mysql++.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <math.h>

#define U_ASSERT(x)  { if(U_FAILURE(x)) {fflush(stdout);fflush(stderr); fprintf(stderr, #x " == %s\n", u_errorName(x)); assert(U_SUCCESS(x)); }}

class Response {
private:
    long cDate;
    xmlDocPtr doc;
    xmlNodePtr body;
    long rid;
    std::string contentType; // = Session.DEFAULT_CONTENT;
    std::string status;
    //	HttpServletRequest req;

    bool aborted;
public:
    //	private static TransformerFactory tff = TransformerFactory.newInstance();
    static const char *STATUS_LEAVING; // = "leaving";
    static const char *STATUS_PENDING; // = "pending";
    static const char *STATUS_DONE; // = "done";
    Response();
    Response(xmlDocPtr doc);
    virtual ~Response();
    Response * setAttribute(std::string key, std::string val);
    Response * setAttribute(std::string key, long val);
    Response * setContentType(std::string type);
    Response * addNode(xmlNodePtr n, std::string ns);
    std::string getStatus();
    void send(struct evhttp_request* req, struct evbuffer* buf);
    void setStatus(std::string status);
    long getRID();
    Response * setRID(long rid);
    long getCDate();
    bool isAborted();
    void setAborted(bool aborted);
};

//typedef xmlNodePtr nodevector;
typedef std::vector< xmlNodePtr > nodevector;
typedef std::vector< xmlNodePtr >::iterator nodeiter;

#endif /* RESPONSE_H_ */
