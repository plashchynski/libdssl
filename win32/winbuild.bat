@ECHO OFF
SET DSSL_LIBS=C:
SETLOCAL EnableDelayedExpansion
SET INCLUDE=%DSSL_LIBS%\openssl-0.9.8g\inc32;%DSSL_LIBS%\zlib-1.2.3\include;%DSSL_LIBS%\WpdPack-4.0.2\Include;%INCLUDE%
SET LIB=%DSSL_LIBS%\openssl-0.9.8g\bin;%DSSL_LIBS%\zlib-1.2.3\lib;%DSSL_LIBS%\WpdPack-4.0.2\Lib;%LIB%
SET PATH=%DSSL_LIBS%\openssl-0.9.8g\bin;%DSSL_LIBS%\zlib-1.2.3\bin;%DSSL_LIBS%\WpdPack-4.0.2\Bin;%PATH%
SET opts=/nologo /platform:Win32 /logcommands /nohtmllog /M1 /useenv
SET conf=Release
FOR %%I IN (%*) DO (SET opt=%%~I
  IF "!opt:~0,1!"=="/" SET opts=!opts! %%I
  IF "!opt!"=="debug" SET conf=Debug
  IF "!opt!"=="release" SET conf=Release)
FOR %%S in (*.sln) DO vcbuild %opts% "/logfile:%%~nS[%conf%].log" %%S "%conf%|Win32"
