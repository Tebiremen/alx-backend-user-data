#!/usr/bin/env python3
'''Encrypting passwords module.
'''
import bcrypt


def hash_password(password: str) -> bytes:
    '''Hash a password using a random salt.
    '''
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    '''Checking if a hash password was formed from the given password.
    '''
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
