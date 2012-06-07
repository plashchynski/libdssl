@ECHO OFF
SET DSSL_LIBS=C:
SETLOCAL EnableDelayedExpansion
SET PATH=%DSSL_LIBS%\openssl-0.9.8g\bin;%DSSL_LIBS%\zlib-1.2.3\bin;%DSSL_LIBS%\WpdPack-4.0.2\Bin;%PATH%
%*
