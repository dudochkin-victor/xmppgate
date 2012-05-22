/*
 * Session.h
 *
 *  Created on: 01.02.2011
 *      Author: blacksmith
 */

#ifndef SESSION_H_
#define SESSION_H_

#include "Response.h"

class Session {
public:

    /**
     * Default HTTP Content-Type header.
     */
    static const char *DEFAULT_CONTENT;

    /**
     * Longest allowable inactivity period (in seconds).
     */
    static const int MAX_INACTIVITY = 30;

    /**
     * Maximum number of simultaneous requests allowed.
     */
    static const int MAX_REQUESTS = 2;

    /*
     * ####### CONSTANTS #######
     */

    /**
     * Default value for longest time (in seconds) that the connection manager
     * is allowed to wait before responding to any request during the session.
     * This enables the client to prevent its TCP connection from expiring due
     * to inactivity, as well as to limit the delay before it discovers any
     * network failure.
     */
    static const int MAX_WAIT; // = 300;

    /**
     * Shortest allowable polling interval (in seconds).
     */
    static const int MIN_POLLING; // = 2;

    /**
     * Time to sleep on reading in MSEC.
     */

    static const char *SESS_START; // = "starting";
    static const char *SESS_ACTIVE; // = "active";
    static const char *SESS_TERM; // = "term";
    bool authidSent; // = false;
    bool streamFeatures; // = false;
    pthread_t thr;
private:
    int init_retry/* = 0*/;
    static const int READ_TIMEOUT = 1;
    static const int SOCKET_TIMEOUT = 6000;
    static const int DEFAULT_XMPPPORT = 5222;
    std::string createSessionID(int len);
    long lastDoneRID;
    std::string authid; // stream id given by remote jabber server
    std::string content; // = DEFAULT_CONTENT;
    //	DocumentBuilder db;
    int hold; // = MAX_REQUESTS - 1;
    //	BufferedReader br;
    bufferevent * evb;
    event_base * base;
    std::string key;
    long lastActive;
    long lastPoll; // = 0;
    int lastSentRid; // = 0;
    //	OutputStreamWriter osw;
    //	TreeMap outQueue;
    std::map<int, Response*> responses;
    
    std::string status; // = SESS_START;
    int sock;
    int port;
    std::string to;
    //	DNSUtil.HostAddress host = null;
    int wait; // = MAX_WAIT;
    std::string xmllang; // = "en";
    bool reinit; // = false;
    bool secure; // = false;
    bool pauseForHandshake; // = false;
    //	Pattern streamPattern;
    //	Pattern stream10Test;
    //	Pattern stream10Pattern;
    std::string readFromSocket(long rid);
    void run();
    static void* helper(void* arg);
    pthread_t tid;
public:
    xmlNodePtr nl;
    std::string sid;
    std::string respbuf; // = "";
    Session(std::string to, std::string route);
    virtual ~Session();
    void start();
    void join();
    Session * setHold(int hold);
    void setKey(const char* val);
    void setLastActive();
    void setLastDoneRID(long rid);
    void setLastPoll();
    int setWait(int wait);
    Session * setXMLLang(std::string xmllang);
    bool isReinit();
    bool isSecure();
    void setReinit(bool reinit);
    void setStatus(std::string status);
    bool isStatus(std::string status);
    void terminate();
    void setSecure(bool secure);
    static Session * getSession(std::string sid);
    Session * setContent(std::string content);
    Response * addResponse(Response * r);
    xmlNodePtr checkInQ(long rid);
    Session * sendNodes(xmlNodePtr nl);
    bool checkValidRID(long rid);
    std::string getAuthid();
    std::string getContent();
    int getHold();
    std::string getKey();
    long getLastActive();
    long getLastPoll();
    Response * getResponse(long rid);
    std::string getSID();
    std::string getTo();
    int getWait();
    std::string getXMLLang();
    int numPendingRequests();
    long getLastDoneRID();
    int createSock(std::string host);
};

#endif /* SESSION_H_ */
