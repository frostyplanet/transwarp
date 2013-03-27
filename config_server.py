#!/usr/bin/env python
# coding:utf-8

import os
log_dir = os.path.join (os.path.dirname (__file__), "log")
log_rotate_size = 20000
log_backup_count = 3
log_level = "DEBUG"
# for log.py

RUN_DIR = os.path.join (os.path.dirname (__file__), "run") 

SERVER_ADDR = ("0.0.0.0", 23000)

ACCEPT_KEYS = [
    "sdfsdr9798798",
]


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
