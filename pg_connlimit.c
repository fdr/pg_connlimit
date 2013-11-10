/*
 * pg_connlimit.c
 *
 * Implements a module to limit how many connections a role may have.
 *
 * This is not unlike "ALTER ROLE CONNECTION LIMIT <connlimit>' except the
 * database of limits is not in the database catalog, which allows
 * disparate-sized databases that are using hot standby to set different
 * connection limits.
 *
 * This module is intended to be loaded with shared_preload_libraries,
 * and configured via the GUC "connlimit.directory".
 *
 * connlimit.directory names a path that is should have a structure
 * like this:
 *
 * connlimit-db/
 * ├── arolename
 * └── yetanotherrolename
 *
 * This applies limits to roles "arolename" and "yetanotherrolename".  To see
 * what these limits are, one can run something like:
 *
 *  $ cat connlimit-db/arolename
 *  10
 *
 * And to set them, one can run something like:
 *
 *  $ echo '30' > connlimit-db/arolename
 *
 * In event the directory or files cannot be read for any reason, the
 * connection limit is not enforced.
 *
 * Copyright (c) 2013, pg_connlimit Contributors
 *
 */
#include "postgres.h"

#include <fcntl.h>
#include <unistd.h>

#include "fmgr.h"
#include "lib/stringinfo.h"
#include "libpq/auth.h"
#include "storage/procarray.h"
#include "utils/acl.h"
#include "utils/elog.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

/* Dynamic linking hooks for Postgres. */
void _PG_init(void);

/* Save other hooks for execution. */
static ClientAuthentication_hook_type prev_ClientAuthentication_hook = NULL;

/* Directory containing role limits. */
static char *connlimitDirectory = NULL;

/* Internal function definitions. */
static void client_auth_hook(Port *port, int status);
static void enforce_limit(char *rolname);
static bool isalphanum(char *str);

/*
 * _PG_init()			- library load-time initialization
 *
 * DO NOT make this static nor change its name!
 *
 * Init the module and set up a ClientAuthentication_hook that applies
 * connection limits to roles.
 */
void
_PG_init(void)
{
	/* Set up GUCs */
	DefineCustomStringVariable(
		"connlimit.directory",
		"The directory to read connection limiting information from.",
		"",
		&connlimitDirectory,
		NULL,
		PGC_SIGHUP,
		GUC_NOT_IN_SAMPLE,
		NULL,
		NULL,
		NULL);

	/* Complain about unexpected settings in the connlimit namespace. */
	EmitWarningsOnPlaceholders("connlimit");

	/* Save any existing hook to call later. */
	prev_ClientAuthentication_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = client_auth_hook;
}

static void
client_auth_hook(Port *port, int status)
{
	/*
	 * May exit the process on account of too many backends for the
	 * role.
	 */
	if (status == STATUS_OK)
		enforce_limit(port->user_name);

	if (prev_ClientAuthentication_hook != NULL)
	{
		/* Pre-existing hook present: call it. */
		prev_ClientAuthentication_hook(port, status);
	}

}

/* Check if the given NUL-terminated string is ASCII-alphanumeric. */
static bool
isalphanum(char *str)
{
	char c;

	c = *str;

	/* An empty string is considered non-alphanumeric */
	if (c == '\0')
		return false;

	do
	{
		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z'))
		{
			str += 1;
			c = *str;
		}
		else
			return false;
	} while (c != '\0');

	return true;
}

static void
enforce_limit(char *rolname)
{
	Oid					 roleid;
	int					 fd;
	StringInfoData		 pathBuf;
	int					 save_errno;
	StringInfoData		 limitBuf;
	ssize_t				 remaining;
	long int			 limit;

	/* Expected GUC is not configured: early exit. */
	if (connlimitDirectory == NULL)
		return;

	roleid = get_role_oid(rolname, true);

	/* Could not locate a matching role: early exit. */
	if (!OidIsValid(roleid))
		return;

	/*
	 * Role is not alphanumeric.  Don't let it be used as input to open(), to
	 * avoid traversal attacks (e.g. contained '.' characters).
	 */
	if (!isalphanum(rolname))
		return;

	/* Compute path to probe for connection limit enforcement. */
	initStringInfo(&pathBuf);
	appendStringInfoString(&pathBuf, connlimitDirectory);
	appendStringInfoString(&pathBuf, "/");
	appendStringInfoString(&pathBuf, rolname);

	/* Save errno so it can later be restored as a courtesy to callers. */
	save_errno = errno;

	/* Try to get a file descriptor to the computed path. */
	do
	{
		errno = 0;
		fd = open(pathBuf.data, O_RDONLY);
	} while (errno == EAGAIN);

	if (errno != 0)
	{
		/* Couldn't open the connection limit file: do not enforce. */
		goto cleanup;
	}

	/* Try to read the limit data from that file descriptor. */
	initStringInfo(&limitBuf);

	/* Leave space for the NUL terminator. */
	remaining = limitBuf.maxlen - sizeof '\0';
	do
	{
		ssize_t n;

		errno = 0;
		n = read(fd, &limitBuf.data[limitBuf.len], remaining - limitBuf.len);

		if (n > 0)
			limitBuf.len += n;
	} while (errno == EAGAIN && limitBuf.len < remaining);

	if (errno != 0 || limitBuf.len == limitBuf.maxlen)
	{
		/*
		 * Couldn't read the file or could not find EOF within the
		 * limitBuf size: do not enforce.
		 */
		goto cleanup_opened;
	}

	/* Add a NUL terminator */
	AssertState(limitBuf.len < limitBuf.maxlen);
	limitBuf.data[limitBuf.len] = '\0';
	limitBuf.len += 1;

	/* Try to parse an integer out of the read data. */
	AssertState(errno == 0);
	limit = strtol(limitBuf.data, NULL, 10);

	if (errno != 0)
	{
		/* Couldn't parse the integer: do not enforce. */
		goto cleanup_opened;
	}

	/*
	 * Check to see if the number of backends is over quota.
	 *
	 * CountUserBackends does not include the current backend this
	 * code is running in yet, so use ">=" to compensate for that.
	 */
	if (CountUserBackends(roleid) >= limit)
	{
		errno = save_errno;
		ereport(FATAL,
				(errcode(ERRCODE_TOO_MANY_CONNECTIONS),
				 errmsg("too many connections for role \"%s\"",
						rolname)));
	}

cleanup_opened:
	pfree(limitBuf.data);
	close(fd);

	/* Fall-through. */
cleanup:
	pfree(pathBuf.data);

	errno = save_errno;
}
