/*
 * Copyright (C) 2009-2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 * Authors: David Zeuthen <davidz@redhat.com>,
 *          Andrew Psaltis <ampsalits@gmail.com>
 */
#ifndef __POLKIT_AGENT_HELPER_PRIVATE_H
#define __POLKIT_AGENT_HELPER_PRIVATE_H

#include <polkit/polkit.h>

/* Development aid: define PAH_DEBUG to get debugging output. Do _NOT_
 * enable this in production builds; it may leak passwords and other
 * sensitive information.
 */
#undef PAH_DEBUG
/* #define PAH_DEBUG */

#ifdef HAVE_SOLARIS
#  define LOG_AUTHPRIV    (10<<3)
#endif

int _polkit_clearenv (void);

/* Reads one newline-terminated line from stdin into @out (newline stripped).
 *
 * Returns 1 on success, -1 on EOF, overflow or error, and 0 if @extra_fd
 * became readable (or hung up) before a full line arrived -- in which case
 * @extra_signalled is set and the caller decides what that means.
 *
 * stdio is deliberately not used for stdin anywhere in the helper: a caller
 * that must wait on stdin and on another descriptor at the same time needs
 * poll(), and poll() cannot see bytes that stdio has already buffered.
 */
int read_line_from_agent (char *out, size_t out_size, int extra_fd, gboolean *extra_signalled);

char *read_cookie (int argc, char **argv);

gboolean send_dbus_message (const char *cookie, const char *user, int pidfd, int uid);

void flush_and_wait (void);

#endif /* __POLKIT_AGENT_HELPER_PRIVATE_H */
