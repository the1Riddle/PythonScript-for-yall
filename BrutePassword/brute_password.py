"""
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Reads a /etc/shadow style password file 
    (that contains username and passwords)
    and try to exhaustive guess the passwords.

    This only supports MD5 hash.
"""

import re
from argparse import ArgumentParser
import logging
import os
import sys
import time
from collections import namedtuple
from queue import Empty
from multiprocessing import (
    JoinableQueue as Queue,
    Process,
    Manager,
)
from passlib.hash import md5_crypt

password_t = namedtuple('passwd', ['username', 'algorithm', 'salt', 'password'])
pattern = re.compile(r"^(?P<username>[a-z]+):\$(?P<alg>\d)"
                     "\$(?P<salt>.+)\$(?P<password>.+)$")

logger = logging.getLogger(os.path.basename(__file__).rstrip('.py'))
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class Worker(Process):
    def __init__(self, id:int, queue:Queue, passwords:list, results:dict):
        super().__init__()
        self._id = id
        self._queue = queue
        self._passwords = passwords
        self._results = results

    def run(self):
        """
        Try every password from the list until it finds one with the same hash as
        hash
        """
        logger.info('worker %d started', self._id)
        while True:
            try:
                user = password_t(*self._queue.get(block=False))
            except Empty:
                break
            counter = 0
            start = time.time()
            for password in self._passwords:
                hashed = md5_crypt.using(salt=user.salt).hash(password)
                # logger.debug('worker %d generated %s for %s', self._id, hashed, password)
                if hashed.split('$')[-1] == user.password:
                    logger.info('found password %s for user %s',
                                password, user.username)
                    self._results[user.username] = password
                    break
                counter += 1
                if (counter % 10000) == 0:
                    logger.debug("worker %d has tried %d passwords "
                                 "(avg rate = %d passwords/s)", self._id, counter,
                                 counter / (time.time() - start))
            self._queue.task_done()
        logger.info('worker %d done', self._id)


def main():
    ag = ArgumentParser()

    ag.add_argument('file', metavar="FILE", type=lambda s: open(s, 'r'),
                    help='specify the input file')
    ag.add_argument('dict', metavar="DICT", type=str,
                    help='spcify the dictionary file to try')
    ag.add_argument('-n', '--max-workers', type=int, default=8,
                    help='specify the maximum number of workers')

    start_time = time.time()
    args = ag.parse_args()
    lines = args.file.read().splitlines()
    args.file.close()
    queue = Queue()
    num_users = 0
    for line in lines:
        if line:  # filter empty lines
            queue.put(tuple(pattern.findall(line)[0]))
            num_users += 1

    if not num_users:
        logger.error("no user was found in password file")
        raise SystemExit(1)

    lines = open(args.dict, 'rb').read().splitlines()
    logger.debug('using password file %s (%d lines)', args.dict, len(lines))

    manager = Manager()
    results = manager.dict()
    for i in range(0, min(args.max_workers, num_users)):
        worker = Worker(i, queue, lines, results)
        worker.daemon = False
        worker.start()

    queue.join()
    print(results)
    logger.info('cracked %d passwords in %6.3f seconds',
                len(results), time.time() - start_time)


if __name__ == '__main__':
    main()
