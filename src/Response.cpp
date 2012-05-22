/*
 * Response.cpp
 * По идее это просто хелпер над xml
 *  Created on: 01.02.2011
 *      Author: blacksmith
 */

#include "Response.h"
#include "Session.h"

const char *Response::STATUS_LEAVING = "leaving";
const char *Response::STATUS_PENDING = "pending";
const char *Response::STATUS_DONE = "done";

/**
 * creates new high level response object specific to http binding
 * responses
 *
 * @param response low level response object
 * @param doc empty document to start with
 */
Response::Response(xmlDocPtr doc) {
    this->doc = doc;
    this->body = xmlNewNode(NULL, BAD_CAST "body");
    xmlNodeSetContent(this->body, BAD_CAST "content");
    xmlDocSetRootElement(doc, this->body);
    xmlSetProp(this->body, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/protocol/httpbind");
    this->cDate = time(NULL);
    setStatus(STATUS_PENDING);
}

Response::Response() {
    this->doc = xmlNewDoc(BAD_CAST "1.0");
    this->body = xmlNewNode(NULL, BAD_CAST "body");
//    xmlNodeSetContent(this->body, BAD_CAST "content");
    xmlDocSetRootElement(doc, this->body);
    xmlSetProp(this->body, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/protocol/httpbind");
    this->cDate = time(NULL);
    setStatus(STATUS_PENDING);
}

Response::~Response() {
    // TODO Auto-generated destructor stub
}

/**
 * adds an attribute to request's body element
 *
 * @param key	attribute key
 * @param val	attribute value
 * @return	the response
 */
Response * Response::setAttribute(std::string key, std::string val) {
    DEBUG("response setAttribute %s %s", key.c_str(), val.c_str());
    xmlSetProp(this->body, BAD_CAST key.c_str(), BAD_CAST val.c_str());
    return this;
}

Response * Response::setAttribute(std::string key, long val) {
    char buf[33];
    memset(buf, '\0', 32);
    sprintf(buf, "%ld", val);
    DEBUG("response setAttribute %s %s", key.c_str(), buf);
    xmlSetProp(this->body, BAD_CAST key.c_str(), BAD_CAST buf);
    return this;
}
/**
 * sets content type header value of low-level response object
 *
 * @param type	the content-type definition e.g. 'text/xml'
 * @return the response
 */
Response * Response::setContentType(std::string type) {
    this->contentType = type;
    return this;
}

/**
 * adds node as child of replies body element
 *
 * @param n The node to add
 * @return Returns the response again
 */
Response *Response::addNode(xmlNodePtr n, std::string ns) {
    DEBUG("response addNode %s", ns.c_str());
    /* make sure we set proper namespace for all nodes
     * which must be 'jabber:client'
     */
//			if (!((Element) n).getAttribute("xmlns").equals(ns))
//				((Element) n).setAttribute("xmlns",ns);
//    xmlNodePtr newNode = xmlNewNode(NULL, BAD_CAST ns.c_str());

    xmlAddChild(this->body, n);
    return this;
}

/**
 * sends this response
 */
void Response::send(struct evhttp_request* req, struct evbuffer* buf) {
//                Transformer tf = tff.newTransformer();
//                tf.setOutputProperty("omit-xml-declaration", "yes");
//                tf.transform(new DOMSource(this.doc.getDocumentElement()), strResult);
//                response.setContentType(this.contentType);

    xmlChar *xmlbuff;
    int buffersize;

    xmlDocDumpMemory(doc, &xmlbuff, &buffersize);
    evhttp_add_header(req->output_headers, "Content-Type", Session::DEFAULT_CONTENT);
    evbuffer_add_printf(buf, "%s", (char *) xmlbuff+22);
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    DEBUG("sent response for %ld [%s] [%s]", this->rid, xmlbuff+22, Session::DEFAULT_CONTENT);
    setStatus(Response::STATUS_DONE);
    xmlFree(xmlbuff);
}

/**
 * @return Returns the status.
 */
std::string Response::getStatus() {
    return status;
}

/**
 * @param status The status to set.
 */
void Response::setStatus(std::string status) {
    DEBUG("response status %s for %ld", status.c_str(), this->rid);
    this->status = status;
}

long Response::getRID() {
    return this->rid;
}

Response * Response::setRID(long rid) {
    this->rid = rid;
    return this;
}

/**
 * @return Returns the cDate.
 */
long Response::getCDate() {
    return cDate;
}

/**
 * @return the req
 */
//	HttpServletRequest Response::getReq() {
//		return req;
//	}

/**
 * @return the aborted
 */
bool Response::isAborted() {
    return aborted;
}

/**
 * @param aborted the aborted to set
 */
void Response::setAborted(bool aborted) {
    this->aborted = aborted;
}
