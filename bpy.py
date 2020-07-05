import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import ssl
import sys
import threading
import urllib.parse
import urllib.request

# ssl._create_default_https_context = ssl._create_unverified_context

token = None

DEBUG = False
UPLOAD_PREFIX = '/_bpy_'

rcs = False
verbose = False


def info(msg):
    frame = sys._getframe(1)
    msg = '[{}:{} {}:{}#{}] {}'.format(os.getpid(), threading.current_thread().name,
                                       frame.f_code.co_name, frame.f_lineno,
                                       frame.f_code.co_filename, msg) if verbose or DEBUG \
        else msg
    print('\033[32m{}\033[0m'.format(msg))


def warn(msg):
    frame = sys._getframe(1)
    msg = '[{}:{} {}:{}#{}] {}'.format(os.getpid(), threading.current_thread().name,
                                       frame.f_code.co_name, frame.f_lineno,
                                       frame.f_code.co_filename, msg) if verbose or DEBUG \
        else msg
    print('\033[35m{}\033[0m'.format(msg))


def err(msg):
    frame = sys._getframe(1)
    msg = '[{}:{} {}:{}#{}] {}'.format(os.getpid(), threading.current_thread().name,
                                       frame.f_code.co_name, frame.f_lineno,
                                       frame.f_code.co_filename, msg) if verbose or DEBUG \
        else msg
    print('\033[31m{}\033[0m'.format(msg))


def strip_slash(string):
    if not string.__contains__('./') and not string.__contains__('//') and not string.__contains__('..'):
        return string[1:] if string.startswith('/') else string
    else:
        slash = strip_slash(string.strip().replace('..', '').replace('./', '')
                            .replace('//', '/'))
        return slash[1:] if slash.startswith('/') else slash


def get_file_listall(file, order, start=0, limit=100, recursion=1, target=None):
    target = target if target else file
    if DEBUG:
        conn = http.client.HTTPSConnection('localhost', 8888, context=ssl._create_unverified_context())
        conn.set_tunnel("pan.baidu.com")
    else:
        conn = http.client.HTTPSConnection("pan.baidu.com")
    payload = ''
    query = {
        'method': 'listall',
        'path': file if file.startswith('/') else '/{}'.format(file),
        'access_token': token,
        'order': order,
        'recursion': recursion,
        'start': start,
        'limit': limit,
        'web': 1,
        'folder': 0
    }
    headers = {
        'Host': 'pan.baidu.com',
    }
    conn.request("GET",
                 "/rest/2.0/xpan/multimedia?{}".format(urllib.parse.urlencode(query)),
                 payload, headers)
    res = conn.getresponse()
    if res.getcode() != http.HTTPStatus.OK:
        return None, "http error {} {}".format(res.getcode(), res.read().decode())
    data = res.read()
    fs = json.loads(data.decode("utf-8"))
    if fs.get('errno') != 0:
        return None, "response error: {}".format(fs.get('errno'))
    if fs.get('list') is None or len(fs.get('list')) == 0:
        path = os.path.dirname(file)
        if path is None or path == '/':
            return None, 'No File'
        else:
            return get_file_listall(path, order, start, limit, recursion, target)
    flist = []
    for l in fs.get('list'):
        if l.get('isdir') == 0 and l.get('path').startswith(target if target.startswith('/') else '/{}'.format(target)):
            flist.append(l)
    return flist, None


def get_file_list(file='/', order='name', start=0, limit=100, recursion=False):
    if recursion:
        return get_file_listall(file, order, start, limit, 1 if recursion else 0)
    conn = http.client.HTTPSConnection("pan.baidu.com") if not DEBUG \
        else http.client.HTTPSConnection('localhost', 8888, context=ssl._create_unverified_context())
    if DEBUG:
        conn.set_tunnel("pan.baidu.com")
    payload = ''
    query = {
        'method': 'list',
        'dir': file if file.startswith('/') else '/{}'.format(file),
        'access_token': token,
        'order': 'name',
        'start': start,
        'limit': limit,
        'web': 1,
        'folder': 0
    }
    headers = {
        'Host': 'pan.baidu.com',
        'Cookie': 'BAIDUID=F082E6512DB8969B46D497B4871AB879:FG=1'
    }
    conn.request("GET",
                 "/rest/2.0/xpan/file?{}".format(urllib.parse.urlencode(query)),
                 payload, headers)
    res = conn.getresponse()
    if res.getcode() != http.HTTPStatus.OK:
        return None, "http error {}".format(res.getcode())
    data = res.read()
    fs = json.loads(data.decode("utf-8"))
    if fs.get('errno') != 0:
        return None, "response error: {}".format(fs.get('errno'))
    if (fs.get('list') is None or len(fs.get('list')) == 0) and recursion:
        return get_file_listall(file, order=order, start=start, limit=limit, recursion=1 if recursion else 0)
    return fs.get('list'), None


def list_file(args):
    if args is None or len(args) == 0:
        args = [UPLOAD_PREFIX]
        info('args is null, use {} instead'.format(args))
    for i in args:
        count = 0
        index = 0
        step = 100
        # data = []
        head, msg = get_file_list(file=strip_slash(i), start=count, recursion=rcs)

        if head is None or len(head) == 0:
            info('no file or path found in {}'.format(i))
            exit(-1)
        for f in head:
            index += 1
            print('{}: {} \033[34m{}\033[0m \033[31m{}\033[0m'
                  .format(str(index).ljust(3), 'file' if f.get('isdir') == 0 else "dir ",
                          f.get('path'), f.get('md5') if f.get('isdir') == 0 else ''))
        while head:
            # data.extend(head)
            if len(head) != step:
                break
            count += step
            head, msg = get_file_list(file=i, start=count, recursion=rcs)
            if head is None or len(head) == 0:
                warn(msg)
                return -1
            for f in head:
                if rcs and f.get('isdir') > 0:
                    pass
                else:
                    index += 1
                    print('{}: {} \033[34m{}\033[0m \033[31m{}\033[0m'
                          .format(str(index).ljust(3), 'file' if f.get('isdir') == 0 else "dir ",
                                  f.get('path'), f.get('md5') if f.get('isdir') == 0 else ''))


def download_file(args):
    pool = args.get('pool')
    link = args.get('link')
    path = args.get('path')
    md5 = args.get('md5')
    length = args.get('length')
    progress = args.get('progress')
    info('download file {} starting...'.format(path))
    headers = {
        # 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'User-Agent': 'pan.baidu.com',
        # 'Host': 'd.pcs.baidu.com',
        # 'Cookie': 'BAIDUID=F082E6512DB8969B46D497B4871AB879:FG=1'
    }
    path = path if not path.startswith('/') else path[1:]
    dpath = os.path.dirname(path)
    if os.path.isfile(dpath):
        os.unlink(dpath)
    if not os.path.exists(dpath):
        os.makedirs(dpath, exist_ok=True)
    u = urllib.parse.urlparse(link)

    dl = None
    while True:
        if u.scheme == 'https':
            conn = http.client.HTTPSConnection(u.netloc) if not DEBUG else \
                http.client.HTTPSConnection(host='localhost', port=8888,
                                            context=ssl._create_unverified_context())
            if DEBUG: conn.set_tunnel(u.netloc)
        else:
            conn = http.client.HTTPConnection(u.netloc) if not DEBUG else \
                http.client.HTTPConnection(host='localhost', port=8888)
            if DEBUG: conn.set_tunnel(u.netloc)
        if not dl:
            conn.request('GET', '{}?{}&access_token={}'.format(u.path, u.query, token), headers=headers)
        else:
            conn.request('GET', '{}?{}'.format(u.path, u.query), headers=headers)
        res = conn.getresponse()
        if res.getcode() == http.HTTPStatus.FOUND:
            dl = res.getheader('location')
            u = urllib.parse.urlparse(dl)
            if dl is None:
                warn('dl err: no location found, {}'.format(res.read().decode()))
                exit(-1)
        elif res.getcode() == http.HTTPStatus.OK:
            with open(path, "wb") as f:
                bs = 1024 * 8
                count = 0
                read = 0
                size = -1
                if progress:
                    progress(count, bs, read, size)
                if "content-length" in headers:
                    size = int(headers["Content-Length"])
                else:
                    size = length
                m = hashlib.md5()
                while True:
                    b = res.read(bs)
                    if not b:
                        break
                    read += len(b)
                    count += 1
                    m.update(b)
                    f.write(b)
                    if progress:
                        progress(count, bs, read, size)
                f.flush()
            if size >= 0 and size > read:
                warn('download file {} not complete: really size is {}, downloaded {}'.format(path, size, count))
                exit(-1)
            if m.digest() != md5:
                warn('download file {} not complete: really md5 is {}; download is {}'.format(path, md5,
                                                                                              m.digest().hex()))
                exit(-2)
            return '{}(size: {}) with {}'.format(path, length, md5)
        else:
            warn('download err: {} {}'.format(res.getcode(), res.read().decode()))
            exit(-3)


def download_list(file):
    fsids = []
    for i in file:
        flist, msg = get_file_list(file=i, recursion=True)
        if flist is None or len(flist) == 0:
            warn(msg)
            exit(-1)
        [fsids.append(f['fs_id']) if not f['isdir'] else {
            warn('{} is dir and empty, will not download'.format(f['path']))
        } for f in flist]

    import concurrent.futures
    start = 0
    step = 100
    end = len(fsids)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        while start < end:
            conn = http.client.HTTPSConnection("pan.baidu.com") if not DEBUG \
                else http.client.HTTPSConnection('localhost', 8888, context=ssl._create_unverified_context())
            if DEBUG:
                conn.set_tunnel("pan.baidu.com")
            query = {
                'method': 'filemetas',
                'access_token': token,
                'dlink': 1,
                'thumbs': 1,
                'fsids': fsids[start:start + step if start + step < end else end]
            }
            start += step
            payload = ''
            headers = {
                'Host': 'pan.baidu.com',
                'Cookie': 'BAIDUID=F082E6512DB8969B46D497B4871AB879:FG=1'
            }
            conn.request("GET",
                         "/rest/2.0/xpan/multimedia?{}".format(urllib.parse.urlencode(query)),
                         payload, headers)
            res = conn.getresponse()
            if res.getcode() != http.HTTPStatus.OK:
                warn("download http error {}".format(res.getcode()))
                exit(-3)
            data = res.read()
            download_data = json.loads(data)
            if download_data is None:
                warn("download response error: no data")
                exit(-2)
            if download_data.get('errno') != 0:
                warn("download response error: {}, msg: {}"
                     .format(download_data.get('errno') if not download_data else '',
                             download_data.get('errmsg') if not download_data else ''))
                exit(-1)
            dl = download_data.get('list')

            # for d in download_list:
            for i in executor.map(download_file, [{'pool': executor, 'link': d['dlink'], 'path': d['path'],
                                                   'md5': d['md5'], 'length': d['size']} for d in dl]):
                info('donwload file {} done'.format(i))


def upload_list(paths):
    info('upload list in {}'.format(paths))
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        fs = []
        for p in paths:
            if not os.path.exists(p):
                warn("no such file {} upload ignored".format(p))
                exit(-1)
            if os.path.isdir(p):
                for root, dirs, files in os.walk(p, followlinks=True):
                    for f in files:
                        fs.append(os.path.join(root, os.path.normpath(f)))
            else:
                fs.append(p)
        for r in executor.map(upload_file, [i for i in fs]):
            info('upload list in {} done'.format(r))


def check_error(func, res):
    d = res.read()
    if res.getcode() != http.HTTPStatus.OK:
        warn('http req error in {}, code: {}, body: {}'.format(func, res.getcode(), d.decode()))
        exit(-1)
    j = json.loads(d)
    if d is None or (j.get('errno') is not None and j.get('errno') != 0):
        warn('http server ret error in {}, code: {}, body: {}'.format(func, j.get('errno'), j))
        exit(-2)
    return j


BLOCK_SIZE = 4 * 1024 * 1024
BEGIN_SIZE = 256 * 1024


def done_upload(file, size, u_id, blocks):
    # https://pan.baidu.com/rest/2.0/xpan/file?method=create
    conn = http.client.HTTPSConnection('pan.baidu.com') if not DEBUG \
        else http.client.HTTPSConnection('localhost', 8888, context=ssl._create_unverified_context())
    if DEBUG: conn.set_tunnel('pan.baidu.com')
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'Keep-Alive',
    }
    query = {
        'method': 'create',
        'access_token': token,
    }
    payload = {
        'path': os.path.join(UPLOAD_PREFIX, os.path.normpath(strip_slash(file))),
        'size': size,
        'isdir': 0,
        'rtype': 2,
        'uploadid': u_id,
        'block_list': json.dumps(blocks),
    }
    conn.request('POST',
                 '/rest/2.0/xpan/file?{}'.format(urllib.parse.urlencode(query)),
                 urllib.parse.urlencode(payload),
                 headers=headers)
    res = conn.getresponse()
    j = check_error(sys._getframe().f_code.co_name, res)
    return '{}({}) => {}(md5:{} size: {})' \
        .format(file, size, os.path.join(UPLOAD_PREFIX, os.path.normpath(strip_slash(file))),
                j.get('md5'), j.get('size'))


def upload_file(file):
    info('upload file {} => {}'.format(file, os.path.join(UPLOAD_PREFIX, os.path.normpath(strip_slash(file)))))
    size = 0

    begin_hash = ''
    slice_hash = []

    with open(file, "rb") as f, \
            concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix='upload_file') as executor:
        am = hashlib.md5()
        while True:
            m = hashlib.md5()
            if not size:
                b = f.read(BEGIN_SIZE)
                am.update(b)
                m.update(b)
                begin_hash = m.hexdigest()
                size += len(b)
                if len(b) < BEGIN_SIZE:
                    slice_hash.append(begin_hash)
                    break
                d = f.read(BLOCK_SIZE - BEGIN_SIZE)
                am.update(d)
                m.update(d)
                size += len(d)
                slice_hash.append(m.hexdigest())
                if len(d) < BLOCK_SIZE - BEGIN_SIZE:
                    break
            m = hashlib.md5()
            b = f.read(BLOCK_SIZE)
            am.update(b)
            m.update(b)
            size += len(b)
            slice_hash.append(m.hexdigest())
            if len(b) < BLOCK_SIZE:
                break
        content_hash = am.hexdigest()
        info("begin_hash: {}\nslice_hash: {}\ncontent_hash:{}".format(begin_hash, slice_hash, content_hash))
        if DEBUG:
            conn = http.client.HTTPSConnection('localhost', 8888, context=ssl._create_unverified_context())
            conn.set_tunnel('pan.baidu.com')
        else:
            conn = http.client.HTTPSConnection('pan.baidu.com')
        headers = {
            'Host': 'pan.baidu.com',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'Keep-Alive',
        }
        query = {
            'method': 'precreate',
            'access_token': token,
        }
        payload = {
            'path': os.path.join(UPLOAD_PREFIX, os.path.normpath(strip_slash(file))),
            'size': size,
            'isdir': 0,
            'autoinit': 1,
            'rtype': 2,
            'block_list': json.dumps(slice_hash),
            'slice-md5': begin_hash,
            'content-md5': content_hash,
        }
        conn.request('POST',
                     '/rest/2.0/xpan/file?{}'.format(urllib.parse.urlencode(query)),
                     urllib.parse.urlencode(payload),
                     headers=headers)
        res = conn.getresponse()
        j = check_error(sys._getframe().f_code.co_name, res)
        u_id = j.get('uploadid')
        f.close()
        if j['return_type'] == 2 or u_id is None:
            warn('upload file {} => {} is already created or existes in there'
                 .format(file, os.path.join(UPLOAD_PREFIX, os.path.normpath(strip_slash(file)))))
            exit(0)
        else:
            for ret in executor.map(upload_block, [{'hash': i, 'file': file, 'id': u_id, 'index': s} for s, i in
                                                   enumerate(slice_hash)]):
                info('upload block {} done'.format(ret))
    return done_upload(file, size, u_id, slice_hash)


def upload_block(args):
    md5 = args.get('hash')
    file = args.get('file')
    u_id = args.get('id')
    index = args.get('index')
    info('upload block {} {} of {} starting...'.format(index, md5, file))
    conn = http.client.HTTPSConnection('d.pcs.baidu.com') if not DEBUG \
        else http.client.HTTPSConnection('localhost', 8888, context=ssl._create_unverified_context())
    if DEBUG: conn.set_tunnel('d.pcs.baidu.com')
    import uuid
    boundary = uuid.uuid4().hex
    headers = {
        'Content-type': 'multipart/form-data; boundary={}'.format(boundary),
        'Connection': 'Keep-Alive',
    }
    query = {
        'method': 'upload',
        'type': 'tmpfile',
        'path': os.path.join(UPLOAD_PREFIX, os.path.normpath(strip_slash(file))),
        'uploadid': u_id,
        'partseq': index,
        'access_token': token,
    }
    payload = []
    payload.append('--{}'.format(boundary).encode())

    payload.append(
        'Content-Disposition: form-data; name="file"; filename="{}"'.format(
            os.path.join(UPLOAD_PREFIX, os.path.normpath(file))).encode())
    payload.append(b'Content-Type: application/octet-stream')
    payload.append(b'Content-Transfer-Encoding: binary')
    payload.append(b'')

    with open(file, 'rb') as f:
        f.seek(index * BLOCK_SIZE)
        d = f.read(BLOCK_SIZE)
    payload.append(d)
    payload.append('--{}--'.format(boundary).encode())

    body = b'\r\n'.join(payload)

    conn.request('POST',
                 '/rest/2.0/pcs/superfile2?{}'.format(urllib.parse.urlencode(query)),
                 body,
                 headers=headers)
    res = conn.getresponse()
    j = check_error(sys._getframe().f_code.co_name, res)
    if j.get('md5') == md5:
        return '{} {} of {} succeed'.format(index, md5, file)
    else:
        return '{} {} of {} mismatch, ret: {}'.format(
            index, md5, file, j.get('md5'))


def main():
    parser = argparse.ArgumentParser(description='bpy for baidu yun',
                                     epilog='v0.1 hello@ifnot.cc')
    ls_help = 'ls list, d download, u upload'
    parser.add_argument('cmd', help=ls_help)
    parser.add_argument('args', nargs='*', metavar='dir', type=str)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-r', '--recursive', action='store_true', help='ls file in recursive mode')

    p = parser.parse_args()

    global token
    token = os.getenv('TOKEN')
    if token is None and not os.path.exists('.token'):
        err('no token')
        exit(-1)
    elif not token:
        with open('.token', 'r') as f:
            token = f.readline().strip()

    if not token:
        err('no token file')
        exit(-2)

    global rcs, verbose
    rcs = p.recursive
    verbose = p.verbose
    if p.cmd == 'ls' or p.cmd == 'l' or p.cmd == 'list':
        list_file(p.args)
    elif p.cmd == 'd' or p.cmd == 'download':
        download_list(p.args)
    elif p.cmd == 'u' or p.cmd == 'upload':
        upload_list(p.args)
    else:
        parser.print_usage()


if __name__ == "__main__":
    main()
