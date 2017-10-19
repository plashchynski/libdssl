/*
** This file is a part of DSSL library.
**
** Copyright (C) 2005-2009, Atomic Labs, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#include "stdinc.h"
/*VC++ needs this include file to compile on Windows Server 2008 */
#ifdef _MSC_VER
	#include <malloc.h>
#endif
#include "errors.h"

short gDsslDebugInit = 0;
short gDsslDebugEnabled = 0;

#ifdef _DEBUG
int NmDebugCatchError( int rc )
{
	printf( "\nDSSL error: %d\n", rc );
	return rc;
}

#endif


static void nmLogCategory( uint32_t category )
{
	switch( category & LG_SEVERITY_MASK )
	{
	case LG_SEVERITY_ERROR: puts( "<error   | " ); break;
	case LG_SEVERITY_MESSAGE: puts( "<message | " ); break;
	case LG_SEVERITY_WARNING: puts( "<warning | " ); break;
	default: puts( "<unknown | " ); break;
	}

	switch( category & ~LG_SEVERITY_MASK )
	{
	case LG_CATEGORY_GENERAL: puts( "general>" ); break;
	case LG_CATEGORY_CAPTURE: puts( "capture>" ); break;
	default: puts( "unknown>" ); break;
	}
}

void nmLogMessage( uint32_t category, const char* fmt, ... )
{
  /*TODO*/
	category;
	fmt;
}

void initializeDsslDebug()
{
	char * envParam = getenv("DSSL_EXTRA_DEBUG");
	gDsslDebugEnabled = 0;

	if (envParam != NULL)
		gDsslDebugEnabled = atoi(envParam);

	gDsslDebugInit = 1;
}

short IsDebugEnabled()	
{
	short ret = 0;

	if (!gDsslDebugInit)
		initializeDsslDebug();

	if (gDsslDebugEnabled)
		ret = 1;

	return ret;
}
