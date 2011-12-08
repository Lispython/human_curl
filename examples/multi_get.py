#http://rarestblog.com/py/multi_get.py.txt

import cStringIO
import sys
import pycurl

import re
def removewww(a):
    return a.replace('www.','')

def domain_from_url(url):
    if re.findall(r'^[a-z]+://', url):
        try: return re.findall('^[a-z]+://(www[0-9-]+\.)?([a-z0-9+\.-]+)', url.strip())[0][1].lower()
        except: return ''#repr(sys.exc_info())
    else:
        domain,_,_ = url.partition('/')
        return domain

def short_domain_from_url(url):
    try:
        parts=domain_from_url(url).split('.')
        return removewww('.'.join(parts[-2:] if parts[-2] not in ('co','net','org','com','blogspot','wordpress') else parts[-3:]))
    except:
        return ''

def reduce_by_domain(urls):
    out = []
    on = {}
    for k in urls:
        if short_domain_from_url(k) not in on:
            on[short_domain_from_url(k)] = 1
            out.append(k)
    return out

def multi_get(wf, urls, debug = 0, num_conn = 100, timeout = 5,
              ua = None, ref = None, percentile = 100, cf = None, follow = 1, ref_dict = None):
    if ua is None:
        ua = 'multi_get'
    queue = []

    wf_keys = dict.fromkeys(wf.keys(),1)

    for url in dict.fromkeys(urls).keys():
        url = url.strip()
        if len(url)>250:
            wf[url]='---'
            continue
        if not url or url[0] == "#" or url in wf_keys:
            continue
        filename = "[%03d]" % (len(queue) + 1)
        queue.append((url, filename))


    if not queue:
        return

    num_urls = len(queue)
    num_conn = min(num_conn, num_urls)
    assert 1 <= num_conn <= 10000, "invalid number of concurrent connections"
    if debug:
        print "PycURL %s (compiled against 0x%x)" % (pycurl.version, pycurl.COMPILE_LIBCURL_VERSION_NUM)

    if debug:
        print "----- Getting", num_urls, "URLs using", num_conn, "connections -----"

    m = pycurl.CurlMulti()
    m.handles = []
    for i in range(num_conn):
        c = pycurl.Curl()
        c.fp = None
        if follow:
            c.setopt(pycurl.FOLLOWLOCATION, 1)
            c.setopt(pycurl.MAXREDIRS, 5)
        c.setopt(pycurl.CONNECTTIMEOUT, timeout)
        c.setopt(pycurl.TIMEOUT, timeout)
        c.setopt(pycurl.NOSIGNAL, 1)
        c.setopt(pycurl.USERAGENT, ua)
        if cf:
            c.setopt(pycurl.COOKIEFILE, cf)
            c.setopt(pycurl.COOKIEJAR, cf)

        if ref: c.setopt(pycurl.REFERER, ref)
        m.handles.append(c)

    from UserString import MutableString

    freelist = m.handles[:]
    num_processed = 0
    bailout = 0
    while num_processed < num_urls:
        if bailout: break
        while queue and freelist:
            url, filename = queue.pop(0)
            if '.pdf' not in url:
                c = freelist.pop()
                if type(url)==type(u''):
                    url=url.encode('utf8', 'replace')
                c.setopt(pycurl.URL, url)
                c.res = cStringIO.StringIO()
                c.setopt(pycurl.WRITEFUNCTION, c.res.write)
                if ref_dict is not None:
                    if ref_dict.get(url, ''):
                        c.setopt(pycurl.REFERER, ref_dict.get(url, ''))

                m.add_handle(c)
                c.filename = filename
                c.url = url
            else:
                wf[url]='---'
                num_urls -= 1
        while 1:
            ret, num_handles = m.perform()
            if ret != pycurl.E_CALL_MULTI_PERFORM:
                break
        while 1:
            num_q, ok_list, err_list = m.info_read()
            for c in ok_list:
                c.fp = None
                m.remove_handle(c)


                text = c.res.getvalue()
                if len(text)>100000: text = ''

                wf[c.url]=text

                try:
                    if debug: print "[ ok] %5s %40s" % (c.filename, c.url[:40])
                except:
                    pass

                freelist.append(c)
            for c, errno, errmsg in err_list:
                c.fp = None
                m.remove_handle(c)
                if debug: print "[err] %5s %40s" % (c.filename, c.url[:40])
                wf[c.url]='---'
                freelist.append(c)
            num_processed = num_processed + len(ok_list) + len(err_list)
            if num_urls:
                if float(num_processed)/num_urls*100 > percentile:
                    bailout = 1
                    break
            if num_q == 0:
                break
        m.select(1.0)

    m.close()

if __name__ == '__main__':
    import time, urllib, cjson

    urls = []
    for query in range(10):
        yql_query = "select * from search.web(%d) where query=\"%s\"" % (100, query)
        url = 'http://query.yahooapis.com/v1/public/yql?q=%s&format=json' % urllib.urlencode({'':yql_query})[1:]
        try:
            url_read = urllib.urlopen(url).read()
            urls += list([i['url'] for i in cjson.decode(url_read)['query']['results']['result']])
        except: pass

    print urls
    urls = reduce_by_domain(urls)
    print "%d URLs" % len(urls)

    res = {}
    import time
    tt = time.time()
    multi_get(res, urls, num_conn = 300, percentile = 80)
    print len(urls)/(time.time()-tt), 'urls per second'
