import os
from .base import *
SECRET_KEY = '!ktcqr7o(gv(6uk1iqz&didubab^g!&i)h%f5kn$s91(2jd0nu'

DEBUG = True

ALLOWED_HOSTS = ['localhost']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'piprecious',
        'USER': 'piprecious',
        'PASSWORD': 'piprecious',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

MINIO_STORAGE_ENDPOINT = '127.0.0.1:9000'
MINIO_STORAGE_ACCESS_KEY = 'exodusexodus'
MINIO_STORAGE_SECRET_KEY = 'exodusexodus'
MINIO_STORAGE_USE_HTTPS = False
MINIO_STORAGE_MEDIA_BUCKET_NAME = 'piprecious-media'
MINIO_STORAGE_STATIC_BUCKET_NAME = 'piprecious-static'
MINIO_STORAGE_AUTO_CREATE_MEDIA_BUCKET = True
MINIO_STORAGE_AUTO_CREATE_STATIC_BUCKET = True