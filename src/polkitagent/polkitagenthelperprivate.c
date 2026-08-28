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
 *          Andrew Psaltis <ampsaltis@gmail.com>
 */

#include "polkitagenthelperprivate.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#ifndef HAVE_CLEARENV
extern char **environ;

int
_polkit_clearenv (void)
{
  if (environ != NULL)
    environ[0] = NULL;
  return 0;
}
#else
int
_polkit_clearenv (void)
{
  return clearenv ();
}
#endif


#define POLKIT_AGENT_MAX_COOKIE 4096
#define AGENT_LINE_BUFFER_SIZE (POLKIT_AGENT_MAX_COOKIE + 2) /* +1 newline, +1 NUL */

/* Bytes read from stdin but not yet handed to a caller. Owning this buffer
 * ourselves -- rather than letting stdio own it -- is what lets a caller
 * poll() stdin alongside another descriptor without losing data.
 */
static char agent_buffer[AGENT_LINE_BUFFER_SIZE];
static size_t agent_buffer_used;

/* Returns 1 and fills @out if a complete line is buffered, 0 if it is not
 * yet, -1 if the line cannot fit in @out.
 */
static int
take_buffered_line (char *out,
                    size_t out_size)
{
  char *newline;
  size_t length;

  newline = memchr (agent_buffer, '\n', agent_buffer_used);
  if (newline == NULL)
    return 0;

  length = newline - agent_buffer;
  if (length + 1 > out_size)
    {
      errno = EOVERFLOW;
      return -1;
    }

  memcpy (out, agent_buffer, length);
  out[length] = '\0';

  agent_buffer_used -= length + 1;
  memmove (agent_buffer, newline + 1, agent_buffer_used);

  return 1;
}

int
read_line_from_agent (char *out,
                      size_t out_size,
                      int extra_fd,
                      gboolean *extra_signalled)
{
  if (extra_signalled != NULL)
    *extra_signalled = FALSE;

  for (;;)
    {
      struct pollfd fds[2];
      nfds_t nfds;
      ssize_t bytes_read;
      int result;

      result = take_buffered_line (out, out_size);
      if (result != 0)
        return result;

      if (agent_buffer_used == sizeof agent_buffer)
        {
          errno = EOVERFLOW;
          return -1;
        }

      fds[0].fd = STDIN_FILENO;
      fds[0].events = POLLIN;
      fds[0].revents = 0;
      nfds = 1;

      if (extra_fd >= 0)
        {
          fds[1].fd = extra_fd;
          fds[1].events = POLLIN;
          fds[1].revents = 0;
          nfds = 2;
        }

      if (poll (fds, nfds, -1) < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }

      /* The extra descriptor is checked first: once it has something to say
       * we stop caring about a password that has not arrived yet.
       */
      if (nfds == 2 && fds[1].revents != 0)
        {
          if (extra_signalled != NULL)
            *extra_signalled = TRUE;
          return 0;
        }

      if (fds[0].revents == 0)
        continue;

      bytes_read = read (STDIN_FILENO,
                         agent_buffer + agent_buffer_used,
                         sizeof agent_buffer - agent_buffer_used);
      if (bytes_read < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (bytes_read == 0)
        return -1; /* EOF */

      agent_buffer_used += bytes_read;
    }
}

char *
read_cookie (int argc, char **argv)
{
  /* As part of CVE-2015-4625, we started passing the cookie
   * on standard input, to ensure it's not visible to other
   * processes.  However, to ensure that things continue
   * to work if the setuid binary is upgraded while old
   * agents are still running (this will be common with
   * package managers), we support both modes.
   */
  if (argc == 3)
    return strdup (argv[2]);
  else
    {
      char buf[AGENT_LINE_BUFFER_SIZE];

      if (read_line_from_agent (buf, sizeof buf, -1, NULL) != 1)
        {
          if (errno != 0)
            perror ("read_line_from_agent");
          return NULL;
        }
      g_strchomp (buf);
      return strdup (buf);
    }
}

gboolean
send_dbus_message (const char *cookie, const char *user, int pidfd, int uid)
{
  PolkitAuthority *authority = NULL;
  PolkitIdentity *identity = NULL;
  PolkitSubject *subject = NULL;
  GError *error;
  gboolean ret;

  ret = FALSE;

  error = NULL;
  authority = polkit_authority_get_sync (NULL /* GCancellable* */, &error);
  if (authority == NULL)
    {
      g_printerr ("Error getting authority: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  identity = polkit_unix_user_new_for_name (user, &error);
  if (identity == NULL)
    {
      g_printerr ("Error constructing identity: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  if (pidfd >= 0 && uid >= 0)
    {
      subject = polkit_unix_process_new_pidfd (pidfd, uid, NULL);
      ret = polkit_authority_authentication_agent_response_with_subject_sync (authority,
                                                                              cookie,
                                                                              identity,
                                                                              subject,
                                                                              NULL,
                                                                              &error);
    }
  else
    ret = polkit_authority_authentication_agent_response_sync (authority,
                                                              cookie,
                                                              identity,
                                                              NULL,
                                                              &error);
  if (!ret)
    {
      g_printerr ("polkit-agent-helper-1: error response to PolicyKit daemon: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  ret = TRUE;

 out:

  if (identity != NULL)
    g_object_unref (identity);

  if (authority != NULL)
    g_object_unref (authority);

  if (subject != NULL)
    g_object_unref (subject);

  return ret;
}

void
flush_and_wait (void)
{
  fflush (stdout);
  fflush (stderr);
#ifdef HAVE_FDATASYNC
  fdatasync (fileno(stdout));
  fdatasync (fileno(stderr));
#else
  fsync (fileno(stdout));
  fsync (fileno(stderr));
#endif
  usleep (100 * 1000);
}
