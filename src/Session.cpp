/*
 * Session.cpp
 *
 *  Created on: 01.02.2011
 *      Author: blacksmith
 */
#include <boost/regex.hpp>
#include "Session.h"
using namespace std;

const char *Session::SESS_START = "starting";
const char *Session::SESS_ACTIVE = "active";
const char *Session::SESS_TERM = "term";
const char *Session::DEFAULT_CONTENT = "text/xml;charset=UTF-8";
const int Session::MIN_POLLING = 5;
const int Session::MAX_WAIT = 300;

void on_read(bufferevent * evb, void * arg) {
    Session *sess = (Session*) arg;
    size_t len = EVBUFFER_LENGTH(evb->input) + 1;
    u_char * data = new u_char[len];
    memset(data, '\0', len);
    size_t read = bufferevent_read(evb, data, len);

    DEBUG("Got data from server. Size = %d %d [%s]", read, len, sess->sid.c_str());

    if (read > 0) {
        DEBUG("Data: %s", data); // Нужно ложить в буффер
        sess->respbuf.append((char*) data);
    }
    delete [] data;
    sess->setLastActive();
}

void on_write(bufferevent * evb, void * arg) {
    DEBUG("Data was successfully sent");
}

void on_error(bufferevent * evb, short what, void * arg) {
    if (what & EVBUFFER_EOF) {
        DEBUG("Server disconnected");
    } else {
        DEBUG("Got an error %d", what);
    }
    event_base_loopbreak((event_base*) arg);
}

Session::~Session() {
    // TODO Auto-generated destructor stub
}

/**
 * this class reflects a session within http binding definition
 *
 */

/*
 * ####### static #######
 */

//	private static Hashtable sessions = new Hashtable();
//
//	private static TransformerFactory tff = TransformerFactory.newInstance();
//

string Session::createSessionID(int len) {
    const char *charlist =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    //  Random rand = new Random();
    sid.clear();
    int clen = strlen(charlist);
    cout << "clen " << clen << endl;
    cout << "cnum:";
    char buff[len + 1];
    memset(buff, '\0', len + 1);
    for (int i = 0; i < len; i++) {
        int cNum = rand() % clen;
        buff[i] = charlist[cNum];
        //sid.append(charlist[cNum], 1);
    }
    cout << buff << endl;
    sid.append(buff);
    DEBUG("createSessionID %s", sid.c_str());
    return sid;
}

map<string, Response*>::iterator resp_itr;

map<string, Session*> sessions;
map<string, Session*>::iterator sess_itr;

Session * Session::getSession(string sid) {
    DEBUG("getSession");
    return sessions[sid];
}

//
//	public static void Session::stopSessions() {
//		for (Enumeration e = sessions.elements(); e.hasMoreElements();)
//			((Session) e.nextElement()).terminate();
//	}
//
//	/***************************************************************************
//	 * END static
//	 */
//

int Session::createSock(string host) {
    DEBUG("createSock");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        cerr << "Failed to create socket" << endl;
        return -1;
    }

    hostent *server = gethostbyname(to.c_str());
    if (server == NULL) {
        cerr << "Failed to get address" << endl;
        return -1;
    }

    sockaddr_in serv_addr;

    bzero((char *) &serv_addr, sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(this->port);

    if (connect(sock, (sockaddr*) & serv_addr, sizeof (serv_addr)) < 0) {
        cerr << "Connection failed" << endl;
        return -1;
    }

    base = event_base_new();
    evb = bufferevent_new(sock,
            & on_read,
            & on_write,
            & on_error,
            this);

    bufferevent_base_set(base, evb);
    bufferevent_enable(evb, EV_WRITE | EV_READ);

    return sock;
}

/**
 * Create a new session and connect to jabber server host denoted by
 * <code>route</code> or <code>to</code>.
 *
 * @param to
 *            domain of the server to connect to.
 * @param route
 *            optional hostname of the server to connect to (might be NULL).
 *
 * @throws UnknownHostException
 * @throws IOException
 */
Session::Session(string to, string route) : to(to), evb(NULL), base(NULL), sock(0), init_retry(0)/* throws UnknownHostException,
 IOException*/ {
    //    this->to = to;
    this->port = DEFAULT_XMPPPORT;
    this->setLastActive();

    //			this.db = DocumentBuilderFactory.newInstance().newDocumentBuilder();

    // сначала пытаемся соедениться через атрибут 'route'.
    if (route.compare("") != 0) {
        DEBUG("Trying to use 'route' attribute to open a socket...");
        //		if (route.startsWith("xmpp:")) {
        //			route = route.substring("xmpp:".length());
        //		}
        //			int i;
        //			// has 'route' the optional port?
        //			if ((i = route.lastIndexOf(":")) != -1) {
        //					int p = Integer.parseInt(route.substring(i + 1));
        //					if (p >= 0 && p <= 65535) {
        //						port = p;
        //						DEBUG(
        //								"...route attribute holds a valid port ("
        //										+ port + ").", 3);
        //					}
        //				route = route.substring(0, i);
        //			}
        //
        DEBUG("Trying to open a socket to '%s', using port %d", route.c_str(), port);
        this->sock = createSock(route);
    }

    // если не смогли соедениться через 'route' пробуем через атрибут 'to'
    if (this->sock <= 0 /*|| !this->sock.isConnected()*/) {

        DEBUG("Trying to use 'to' attribute to open a socket...");
        //			host = DNSUtil.resolveXMPPServerDomain(to, DEFAULT_XMPPPORT);
        DEBUG("Trying to open a socket to '%s', using port %d", to.c_str(), port); //host.getHost() host.getPort()
        this->sock = createSock(to);
    }

    // здесь у нас должно быть уже соединение
    if (this->sock <= 0) // this.sock.isConnected()
        DEBUG("Succesfully connected to %s", to.c_str());

    // create unique session id
    while (sessions[createSessionID(24)] != NULL) {
    }

    DEBUG("creating session with id %s", this->sid.c_str());
    // register session
    sessions[this->sid] = this;
    //        this.br = new BufferedReader(new InputStreamReader(this.sock.getInputStream(), "UTF-8"));
    this->setStatus(Session::SESS_ACTIVE);
}

void Session::start() {
    pthread_create(&tid, 0, helper, this);
}

void Session::join() {
    int* status = 0;
    pthread_join(tid, (void**) &status);
}

void Session::run() {
    string dataStream;
    dataStream.append("<stream:stream to='").append(this->to).append("' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>");
    const char * data = dataStream.c_str();
    DEBUG("WRITE TO SERVER [%s]", data);
    if (evb == NULL) DEBUG("EVB IS NULL");
    else
        bufferevent_write(evb, data, strlen(data));
    event_base_loop(base, 0);

    //  for (int i = 0; i < 10; ++i) {
    std::cout << "This is thread #" << to << " running." << std::endl;
    //     sleep(1);
    //  }
}

void* Session::helper(void* arg) {
    Session* t = reinterpret_cast<Session*> (arg);
    t->run();
    pthread_exit(0);
}

/**
 * Adds new response to list of known responses. Truncates list to allowed
 * size.
 *
 * @param r
 *            the response to add
 * @return this session object
 */
Response * Session::addResponse(Response * r) {
    while ((this->responses.size() > 0) && (this->responses.size() >= Session::MAX_REQUESTS)) {
        //TODO delete response
        this->responses.erase(this->responses.begin());
    }
    this->responses[r->getRID()] = r;
    return r;
}

/**
 * checks InputStream from server for incoming packets blocks until request
 * timeout or packets available
 *
 * @return nl - NodeList of incoming Nodes
 */

xmlNodePtr Session::checkInQ(long rid)/* throws IOException*/ {

    nl = NULL;
    if (respbuf.length() == 0) {
        DEBUG("WAIT FOR SERVER RESPONSE");
        sleep(READ_TIMEOUT);
    }
    DEBUG("respbuf: [%s]", this->respbuf.c_str());
    if (init_retry < 1000 && (this->authid == NULL || this->isReinit())
            && respbuf.length() > 0) {
        init_retry++;

        // Паттерны
        boost::regex streamPattern(".*<stream:stream[^>]*id=['|\"]([^'|^\"]+)['|\"][^>]*>.*");
        boost::regex stream10Pattern(".*<stream:stream[^>]*id=['|\"]([^'|^\"]+)['|\"][^>]*>.*(<stream.*)$");
        boost::regex stream10Test(".*<stream:stream[^>]*version=['|\"]1.0['|\"][^>]*>.*");

        if (boost::regex_search(respbuf.c_str(), stream10Test)) {
            boost::cmatch matches;
            boost::regex_match(respbuf.c_str(), matches, stream10Pattern);
            if (matches.size() > 1) {
                this->authid = string(matches[1].first, matches[1].second);
                this->respbuf = string(matches[2].first, matches[2].second);

                DEBUG("AUTHID: [%d] [%s]", matches.size(), this->authid.c_str());
                DEBUG("INQU: [%d] [%s]", matches.size(), this->respbuf.c_str());
                // whether there are stream features present we need to
                // filter them and strip (start)tls information
                streamFeatures = respbuf.length() > 0;
            } else {
                DEBUG("failed to get stream features [%d] [%s]", matches.size(), respbuf.c_str());
                sleep(5);
                return this->checkInQ(rid); // retry
            }
        } else {
            // legacy jabber stream
            boost::cmatch matches;
            boost::regex_match(respbuf.c_str(), matches, streamPattern);
            DEBUG("LEGACY STREAM [%s]", this->respbuf.c_str());
            if (matches.size() > 0) {
                this->authid = string(matches[1].first, matches[1].second);
                boost::regex legacyPattern("asd.*");
                boost::regex_match(respbuf.c_str(), matches, legacyPattern);
                if (matches.size() > 0) {
                    DEBUG("MATCHES: [%d]", matches.size());
                    string m(matches[1].first, matches[1].second);
                    DEBUG("MATCH: [%s]", m.c_str());
                }
            } else {
                DEBUG("failed to get authid");
                sleep(5);
                return this->checkInQ(rid); // retry
            }
        }
        init_retry = 0; // reset
    } else DEBUG("ACHTUNG [%d] [%d] [%s] [%d]", respbuf.length(), init_retry, this->authid.c_str(), this->isReinit());

    // try to parse it
    if (respbuf.length() != 0) {
        try {
            /*
             * wrap respbuf with element so that multiple nodes can be
             * parsed
             */
            std::string buf;
            xmlDocPtr doc;
            if (streamFeatures) {
                buf.append("<doc>");
                buf.append(respbuf);
                buf.append("</doc>");
                try {
                    doc = xmlReadMemory(buf.c_str(), buf.length(), "noname1.xml", NULL, 0);
                } catch (exception e) {
                    DEBUG("EXCEPTION");
                }
            } else {
                buf.append("<doc xmlns='jabber:client'>");
                buf.append(respbuf);
                buf.append("</doc>");
                // try
                doc = xmlReadMemory(buf.c_str(), buf.length(), "noname2.xml", NULL, XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
                if (doc == NULL) {
                    buf.clear();
                    buf.append(respbuf);
                    doc = xmlReadMemory(buf.c_str(), buf.length(), "noname3.xml", NULL, XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_RECOVER);
                    DEBUG("LEGACY DOC [%s]", doc);
                }

                // catch (SAXException sex)
                // { stream closed?
                // doc = db.parse("<stream:stream>" + respbuf);
                // this.terminate();
                // }
            }

            if (doc != NULL) {
                nl = xmlDocGetRootElement(doc); // nl = doc.getFirstChild().getChildNodes();
            }
            DEBUG("PARSE [%s]", buf.c_str());
            if (streamFeatures) { // check for starttls
                //                for (int i = 0; i < nl.item(0).getChildNodes().getLength(); i++) {
                //                    if (nl.item(0).getChildNodes().item(i).getNodeName().equals("starttls")) {
                //                        if (!this.isReinit()) {
                //                            JHBServlet.dbg("starttls present, trying to use it");
                //                            this.osw.write("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
                //                            this.osw.flush();
                //                            string response = this->respbuf; //this.readFromSocket(rid);
                //                            DEBUG("[%s]", response);
                //
                //                            try {
                //                                SSLSocketFactory sslFact = (SSLSocketFactory) SSLSocketFactory.getDefault();
                //                                SSLSocket tls;
                //                                tls = (SSLSocket) sslFact.createSocket(this.sock, this.sock
                //                                        .getInetAddress()
                //                                        .getHostName(), this.sock
                //                                        .getPort(), false);
                //                                tls.addHandshakeCompletedListener(new HandShakeFinished(this));
                //                                this.pauseForHandshake = true;
                //                                DEBUG("initiating handshake");
                //                                tls.startHandshake();
                //                                while (this.pauseForHandshake) {
                //                                    DEBUG(".");
                //                                    sleep(5);
                //                                }
                //                                DEBUG("TLS Handshake complete");
                //
                //                                this.sock = tls;
                //                                this.sock.setSoTimeout(SOCKET_TIMEOUT);
                //                                this.br = new SSLSocketReader((SSLSocket) tls);
                //                                this.osw = new OutputStreamWriter(tls.getOutputStream(), "UTF-8");
                //                                this.respbuf = ""; // reset
                //                                this->setReinit(true);
                //                                this.osw.write("<stream:stream to='" + this.to + "' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'" + ">");
                //                                this.osw.flush();
                //
                //                                return this.checkInQ(rid);
                //                            } catch (Exception ssle) {
                //                                DEBUG("STARTTLS failed: " + ssle.tostring());
                //                                this->setReinit(false);
                //                                if (this.isSecure()) {
                //                                    if (!this.sock.getInetAddress().getHostName().equals("localhost")
                //                                            && !this.getResponse(rid).getReq().getServerName().equals(
                //                                            this.sock.getInetAddress().getHostName())) {
                //                                        JHBServlet.dbg("secure connection requested but failed");
                //                                        throw new IOException();
                //                                    } else {
                //                                        // we trust localhost and hostnames
                //                                        // that are the same as ours
                //                                        JHBServlet.dbg("secure requested and we're local");
                //                                    }
                //
                //                                } else {
                //                                    JHBServlet.dbg("tls failed but we don't need to be secure");
                //                                }
                //                                if (this.sock.isClosed()) {
                //                                    DEBUG("socket closed");
                //                                    // reconnect
                //                                    Socket s = new Socket();
                //                                    s.connect(this.sock.getRemoteSocketAddress(), SOCKET_TIMEOUT);
                //                                    this.sock = s;
                //                                    this.sock.setSoTimeout(SOCKET_TIMEOUT);
                //                                    this.br = new BufferedReader(new InputStreamReader(this.sock.getInputStream(), "UTF-8"));
                //                                    this.osw = new OutputStreamWriter(this.sock.getOutputStream(), "UTF-8");
                //                                    this.respbuf = ""; // reset
                //                                    this->setReinit(true);
                //                                    this.osw.write("<stream:stream to='" + this.to + "' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>");
                //                                    this.osw.flush();
                //                                    return this.checkInQ(rid);
                //                                }
                //                            }
                //                        } else
                //                            nl.item(0).removeChild(nl.item(0).getChildNodes().item(i));
                //                    }
                //                }
            }
            respbuf.clear(); // reset!
        } catch (exception sex3) { /* skip this */
            this->setReinit(false);
            DEBUG("failed to parse respbuf: [%s]", respbuf.c_str());
            return NULL;
        }
    }
    this->setReinit(false);
    this->setLastActive();
    return nl;
}

//	private class HandShakeFinished implements
//			javax.net.ssl.HandshakeCompletedListener {
//		private Session sess;
//
//		public HandShakeFinished(Session sess) {
//			this.sess = sess;
//		}
//
//		public void handshakeCompleted(
//				javax.net.ssl.HandshakeCompletedEvent event) {
//
//			DEBUG("startTLS: Handshake is complete", 2);
//
//			this.sess.pauseForHandshake = false;
//			return;
//		}
//}

/**
 * Checks whether given request ID is valid within context of this session.
 *
 * @param rid
 *            Request ID to be checked
 * @return true if rid is valid
 */
bool Session::checkValidRID(long rid) {
    if ((rid <= (this->responses.begin()->first + MAX_REQUESTS))
            && (rid >= this->responses.begin()->first))
        return true;
    else {
        DEBUG("invalid request id: %ld (last: %ld)", rid,
                +this->responses.begin()->first);
        return false;
    }
}

string Session::getAuthid() {
    return this->authid;
}

string Session::getContent() {
    return this->content;
}

int Session::getHold() {
    return this->hold;
}

/**
 * @return Returns the key.
 */
string Session::getKey() {
    return key;
}

/**
 * @return Returns the lastActive.
 */
long Session::getLastActive() {
    return lastActive;
}

/**
 * @return Returns the lastPoll.
 */
long Session::getLastPoll() {
    return lastPoll;
}

/**
 * lookup response for given request id
 *
 * @param rid
 *            Request id associated with response
 * @return the response if found, NULL otherwise
 */
Response * Session::getResponse(long rid) {
    return this->responses[rid];
}

string Session::getSID() {
    return this->sid;
}

/*
 * ######## getters #########
 */

string Session::getTo() {
    return this->to;
}

int Session::getWait() {
    return this->wait;
}

string Session::getXMLLang() {
    //		return this.xmllang;
    return NULL; //DV
}

int Session::numPendingRequests() {
    int num_pending = 0;
    //		Iterator it = this.responses.values().iterator();
    //		while (it.hasNext()) {
    //			Response r = (Response) it.next();
    //			if (!r.getStatus().equals(Response.STATUS_DONE))
    //				num_pending++;
    //		}
    return num_pending;
}

long Session::getLastDoneRID() {
    return this->lastDoneRID;
}

/**
 * reads from socket
 *
 * @return string that was read
 */

string Session::readFromSocket(long rid) /*throws IOException*/ {

}

/**
 * sends all nodes in list to remote jabber server make sure that nodes get
 * sent in requested order
 *
 * @param nl
 *            list of nodes to send
 * @return the session itself
 */

Session * Session::sendNodes(xmlNodePtr nl) {
    DEBUG("RESPBUF: [%s]", this->respbuf.c_str());
    xmlChar *xmlbuff;
    int buffersize;

    // build a string
    xmlNodePtr body;
    if (this->isReinit()) {
        DEBUG("Reinitializing Stream!");
        string dataStream;
        dataStream.append("<stream:stream to='").append(this->to).append("' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>");
        const char * data = dataStream.c_str();
        DEBUG("WRITE TO SERVER [%s]", data);
        bufferevent_write(evb, data, strlen(data));
        return this;
    } else {
        xmlNodePtr cur = nl->xmlChildrenNode;
        if (cur) {
            xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
            xmlDocSetRootElement(doc, cur);
            xmlDocDumpMemory(doc, &xmlbuff, &buffersize);
            xmlbuff[strlen((char*) xmlbuff) - 1] = '\0';
            bufferevent_write(evb, (char *) xmlbuff + 22, strlen((char*) xmlbuff) - 22);
            DEBUG("WRITE TO SERVER [%s] [%d]", xmlbuff + 22, strlen((char*) xmlbuff) - 22);
            xmlFree(xmlbuff);
        }
        return this;
    }
}

Session * Session::setContent(string content) {
    this->content = content;
    return this;
}

/*
 * ######## setters #########
 */

Session * Session::setHold(int hold) {
    //		if (hold < MAX_REQUESTS && hold >= 0)
    //			this.hold = hold;
    return this;
}

/**
 * @param key
 *            The key to set.
 */
void Session::setKey(const char* val) {
    DEBUG("SETKEY [%s]", val);
    this->key.clear();
    this->key.append(val);
}

/**
 * set lastActive to current timestamp.
 */
void Session::setLastActive() {
    this->lastActive = time(NULL);
}

void Session::setLastDoneRID(long rid) {
    this->lastDoneRID = rid;
}

/**
 * set lastPoll to current timestamp.
 */
void Session::setLastPoll() {
    this->lastPoll = time(NULL);
}

int Session::setWait(int wait) {
    if (wait < 0)
        wait = 0;
    if (wait > Session::MAX_WAIT)
        wait = Session::MAX_WAIT;
    this->wait = wait;
    return wait;
}

Session * Session::setXMLLang(string xmllang) {
    //		this.xmllang = xmllang;
    return this;
}

/**
 * @return Returns the reinit.
 */
bool Session::isReinit() {
    return reinit;
}

/**
 * @return the secure
 */
bool Session::isSecure() {
    return secure;
}

/**
 * @param reinit
 *            The reinit to set.
 */
void Session::setReinit(bool reinit) {
    this->reinit = reinit;
}

void Session::setStatus(string status) {
    this->status = status;
}

bool Session::isStatus(string status) {
    //		return (this.status == status);
    return false; //DV
}

/**
 * kill this session
 *
 */
void Session::terminate() {
    DEBUG("terminating session %s", this->getSID().c_str());
    this->setStatus(SESS_TERM);
    string dataStream;
    dataStream.append("</stream:stream>");
    const char * data = dataStream.c_str();
    if (evb == NULL) DEBUG("EVB IS NULL");
    else
        bufferevent_write(evb, data, strlen(data));
    //  this.sock.notifyAll();
    //    bufferevent_free(evb);
    //    event_base_free(base);
    sessions.erase(this->sid); //TODO delete this
}

/**
 * @param secure
 *            the secure to set
 */
void Session::setSecure(bool secure) {
    this->secure = secure;
}
