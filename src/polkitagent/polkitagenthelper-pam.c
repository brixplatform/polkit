/*
 * Copyright (C) 2008, 2010 Red Hat, Inc.
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
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#include "polkitagenthelperprivate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <security/pam_appl.h>

#include <polkit/polkit.h>

#ifndef SO_PEERPIDFD
#  if defined(__parisc__)
#    define SO_PEERPIDFD 0x404B
#  elif defined(__sparc__)
#    define SO_PEERPIDFD 0x0056
#  elif defined(__linux__)
#    define SO_PEERPIDFD 77
#  endif
#endif

/* The stack every agent has always been authenticated against. It converses
 * with the agent over stdin/stdout and is expected to ask for a password.
 */
#define PAM_SERVICE_NAME "polkit-1"

/* An optional second stack, run concurrently with the first, for
 * authentication that takes time rather than input -- a fingerprint, a
 * smartcard tap. It is given a conversation that answers nothing, so it must
 * not prompt. Distributions that do not ship it get exactly the behaviour
 * polkit had before this existed.
 */
#define PAM_SERVICE_NAME_CONCURRENT "polkit-1-biometric"

/* Where the above is looked for. Linux-PAM reads both, preferring the
 * administrator's copy in the first.
 */
static const char *pam_service_directories[] = { "/etc/pam.d", "/usr/lib/pam.d" };

/* Single byte written back by the concurrent child to report its verdict. */
#define CONCURRENT_VERDICT_SUCCESS 'y'

/* Shared with the conversation function so that a password prompt nobody is
 * going to answer stops being waited on the moment the other stack wins.
 */
typedef struct
{
  int verdict_fd;             /* read end of the child's pipe, -1 once done */
  gboolean concurrent_won;
} ConversationData;

static int conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data);
static int null_conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data);

static void
send_to_helper (const gchar *str1,
                const gchar *str2)
{
  char *escaped;
  char *tmp2;
  size_t len2;

  tmp2 = g_strdup(str2);
  g_assert (tmp2 != NULL);
  len2 = strlen(tmp2);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing `%s ' to stdout\n", str1);
#endif /* PAH_DEBUG */
  fprintf (stdout, "%s ", str1);

  if (len2 > 0 && tmp2[len2 - 1] == '\n')
    tmp2[len2 - 1] = '\0';
  escaped = g_strescape (tmp2, NULL);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing `%s' to stdout\n", escaped);
#endif /* PAH_DEBUG */
  fprintf (stdout, "%s", escaped);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing newline to stdout\n");
#endif /* PAH_DEBUG */
  fputc ('\n', stdout);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: flushing stdout\n");
#endif /* PAH_DEBUG */
  fflush (stdout);

  g_free (escaped);
  g_free (tmp2);
}

/* The whole of what it means to authenticate: the stack ran, the account is
 * permitted, and the user it ended up authenticating is the one we asked
 * about. Both the password stack and the concurrent stack must clear all
 * three, so neither can be a weaker way in than the other.
 */
static gboolean
authenticate_with_pam (const char *service,
                       const char *user_to_auth,
                       struct pam_conv *conversation)
{
  pam_handle_t *pam_h = NULL;
  const void *authed_user;
  gboolean authenticated = FALSE;
  int rc;

  rc = pam_start (service, user_to_auth, conversation, &pam_h);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_start failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  rc = pam_set_item (pam_h, PAM_RUSER, user_to_auth);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_set_item failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  /* is user really user? */
  rc = pam_authenticate (pam_h, 0);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_authenticate failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  /* permitted access? */
  rc = pam_acct_mgmt (pam_h, 0);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_acct_mgmt failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  /* did we auth the right user? */
  rc = pam_get_item (pam_h, PAM_USER, &authed_user);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_get_item failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  if (strcmp (authed_user, user_to_auth) != 0)
    {
      fprintf (stderr, "polkit-agent-helper-1: Tried to auth user '%s' but we got auth for user '%s' instead",
               user_to_auth, (const char *) authed_user);
      goto out;
    }

  authenticated = TRUE;

out:
  if (pam_h != NULL)
    pam_end (pam_h, rc);
  return authenticated;
}

static gboolean
pam_service_exists (const char *service)
{
  gsize i;

  for (i = 0; i < G_N_ELEMENTS (pam_service_directories); i++)
    {
      char *path;
      gboolean found;

      path = g_build_filename (pam_service_directories[i], service, NULL);
      found = g_file_test (path, G_FILE_TEST_IS_REGULAR);
      g_free (path);

      if (found)
        return TRUE;
    }

  return FALSE;
}

/* Runs PAM_SERVICE_NAME_CONCURRENT in a child process and returns the read
 * end of the pipe it will report its verdict on, or -1 if no such stack is
 * configured.
 *
 * A separate process rather than a thread: PAM is not thread-safe, and a
 * module that wedges must be killable without taking the password prompt
 * down with it. The child never touches the agent's stdin or stdout, so the
 * protocol on those descriptors stays exactly what it was and every existing
 * agent keeps working unmodified.
 */
static int
start_concurrent_authentication (const char *user_to_auth,
                                 pid_t *out_child)
{
  struct pam_conv conversation;
  int pipe_fds[2];
  pid_t child;
  int devnull;
  char verdict;

  *out_child = -1;

  if (!pam_service_exists (PAM_SERVICE_NAME_CONCURRENT))
    return -1;

  if (pipe (pipe_fds) != 0)
    {
      syslog (LOG_NOTICE, "could not create pipe for %s: %m", PAM_SERVICE_NAME_CONCURRENT);
      return -1;
    }

  child = fork ();
  if (child < 0)
    {
      syslog (LOG_NOTICE, "could not fork for %s: %m", PAM_SERVICE_NAME_CONCURRENT);
      close (pipe_fds[0]);
      close (pipe_fds[1]);
      return -1;
    }

  if (child > 0)
    {
      close (pipe_fds[1]);
      /* Also done in the child, so that whoever gets there first has put it
       * in its own process group before the race can be decided.
       */
      setpgid (child, child);
      *out_child = child;
      return pipe_fds[0];
    }

  /* Child. The agent's descriptors are replaced before running any PAM
   * module, so that nothing the concurrent stack does can be mistaken for a
   * message from the conversation the agent is listening to.
   */
  close (pipe_fds[0]);

  /* Its own process group, so that losing the race takes down anything the
   * stack started as well as the stack itself. A module that leaks a process
   * still holding the reader would make the next authentication fail.
   */
  setpgid (0, 0);

  devnull = open ("/dev/null", O_RDWR);
  if (devnull >= 0)
    {
      dup2 (devnull, STDIN_FILENO);
      dup2 (devnull, STDOUT_FILENO);
      if (devnull > STDERR_FILENO)
        close (devnull);
    }

  conversation.conv = null_conversation_function;
  conversation.appdata_ptr = NULL;

  verdict = authenticate_with_pam (PAM_SERVICE_NAME_CONCURRENT, user_to_auth, &conversation)
            ? CONCURRENT_VERDICT_SUCCESS : 'n';

  /* A short write or a dead parent both mean nobody is listening any more. */
  if (write (pipe_fds[1], &verdict, 1) != 1)
    _exit (1);

  _exit (verdict == CONCURRENT_VERDICT_SUCCESS ? 0 : 1);
}

static void
stop_concurrent_authentication (pid_t child,
                                int verdict_fd)
{
  if (verdict_fd >= 0)
    close (verdict_fd);

  if (child <= 0)
    return;

  /* The whole group, and SIGKILL rather than SIGTERM: the child may be inside
   * a PAM module that installed its own handler, and there is nothing either
   * it or anything it spawned needs to clean up that exiting will not.
   */
  if (kill (-child, SIGKILL) != 0 && errno == ESRCH)
    kill (child, SIGKILL);
  while (waitpid (child, NULL, 0) < 0 && errno == EINTR)
    ;
}

int
main (int argc, char *argv[])
{
  int rc;
  int pidfd = -1;
  int uid = -1;
  int errval = 1;
  const char *user_to_auth;
  char *user_to_auth_free = NULL;
  char *cookie = NULL;
  struct pam_conv pam_conversation;
  ConversationData conversation_data = { -1, FALSE };
  pid_t concurrent_child = -1;

  rc = 0;

  char *lang = getenv("LANG");
  char *language = getenv("LANGUAGE");
  char *lc_messages = getenv("LC_MESSAGES");

  /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
  if (_polkit_clearenv () != 0)
    goto error;

  /* set a minimal environment */
  setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

  if(lang)
      setenv("LANG",lang,0);
  if(language)
      setenv("LANGUAGE",language,0);
  if(lc_messages)
      setenv("LC_MESSAGES",lc_messages,0);

  /* check that we are setuid root */
  if (geteuid () != 0)
    {
      gchar *s;

      fprintf (stderr, "polkit-agent-helper-1: needs to be setuid root\n");

      /* Special-case a very common error triggered in jhbuild setups */
      s = g_strdup_printf ("Incorrect permissions on %s (needs to be setuid root)", argv[0]);
      send_to_helper ("PAM_ERROR_MSG", s);
      g_free (s);
      goto error;
    }

  openlog ("polkit-agent-helper-1", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

  /* check for correct invocation */
  if (!(argc == 2 || argc == 3))
    {
      syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
      fprintf (stderr, "polkit-agent-helper-1: wrong number of arguments. This incident has been logged.\n");
      goto error;
    }

#ifdef SO_PEERPIDFD
  /* We are socket activated and the socket has been set up as stdio/stdout, read user from it */
  if (argv[1] != NULL && strcmp (argv[1], "--socket-activated") == 0)
    {
      socklen_t socklen = sizeof(int);
#ifdef SO_PEERCRED
      struct ucred ucred;
#endif

      user_to_auth_free = read_cookie (argc, argv);
      if (!user_to_auth_free)
        goto error;
      user_to_auth = user_to_auth_free;

      rc = getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &socklen);
      if (rc < 0)
        {
          if (errno == ENOPROTOOPT || errno == ENODATA)
            {
              syslog (LOG_ERR, "Pidfd not supported on this platform, disable polkit-agent-helper.socket and use setuid helper");
              fprintf (stderr, "polkit-agent-helper-1: pidfd not supported on this platform, disable polkit-agent-helper.socket and use setuid helper.\n");
            }
          if (errno == EINVAL)
            {
              syslog (LOG_ERR, "Caller already exited, unable to get pidfd");
              fprintf (stderr, "polkit-agent-helper-1: caller already exited, unable to get pidfd.\n");
            }

          goto error;
        }

#ifdef SO_PEERCRED
      socklen = sizeof(ucred);
      rc = getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen);
#else
      rc = -1;
#endif
      if (rc < 0)
        {
          syslog (LOG_ERR, "Unable to get credentials from socket");
          fprintf (stderr, "polkit-agent-helper-1: unable to get credentials from socket.\n");
          goto error;
        }

#ifdef SO_PEERCRED
      uid = ucred.uid;
#endif
    }
  else
#endif
    user_to_auth = argv[1];

  cookie = read_cookie (argc, argv);
  if (!cookie)
    goto error;

  if (getuid () != 0)
    {
      /* check we're running with a non-tty stdin */
      if (isatty (STDIN_FILENO) != 0)
        {
          syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
          fprintf (stderr, "polkit-agent-helper-1: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
          goto error;
        }
    }

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: user to auth is '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

  pam_conversation.conv        = conversation_function;
  pam_conversation.appdata_ptr = &conversation_data;

  /* A stack that can succeed without being asked anything runs alongside the
   * one that talks to the agent, so that reaching for the reader and reaching
   * for the keyboard are both answered promptly. PAM conversations are
   * serial, which is why this has to be a second conversation rather than
   * another module in the first one.
   */
  conversation_data.verdict_fd = start_concurrent_authentication (user_to_auth, &concurrent_child);

  if (!authenticate_with_pam (PAM_SERVICE_NAME, user_to_auth, &pam_conversation) &&
      !conversation_data.concurrent_won)
    {
      /* if run via systemd socket, failed authentication won't taint the system using SuccessExitStatus=2*/
      errval = 2;
      goto error;
    }

  stop_concurrent_authentication (concurrent_child, conversation_data.verdict_fd);
  concurrent_child = -1;
  conversation_data.verdict_fd = -1;

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully authenticated user '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: sending D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */

  /* now send a D-Bus message to the PolicyKit daemon that
   * includes a) the cookie; b) the user we authenticated;
   * c) the pidfd and uid of the caller, if socket-activated
   */
  if (!send_dbus_message (cookie, user_to_auth, pidfd, uid))
    {
#ifdef PAH_DEBUG
      fprintf (stderr, "polkit-agent-helper-1: error sending D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */
      goto error;
    }

  free (cookie);
  free (user_to_auth_free);
  if (pidfd >= 0)
    close (pidfd);

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully sent D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */

  fprintf (stdout, "SUCCESS\n");
  flush_and_wait();
  return 0;

error:
  free (cookie);
  free (user_to_auth_free);
  if (pidfd >= 0)
    close (pidfd);
  stop_concurrent_authentication (concurrent_child, conversation_data.verdict_fd);

  fprintf (stdout, "FAILURE\n");
  flush_and_wait();
  return errval;
}

static int
conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
  struct pam_response *aresp;
  char buf[PAM_MAX_RESP_SIZE];
  int i;

  ConversationData *conversation_data = data;

  if (n <= 0 || n > PAM_MAX_NUM_MSG)
    return PAM_CONV_ERR;

  if ((aresp = calloc(n, sizeof *aresp)) == NULL)
    return PAM_BUF_ERR;

  for (i = 0; i < n; ++i)
    {
      aresp[i].resp_retcode = 0;
      aresp[i].resp = NULL;
      switch (msg[i]->msg_style)
        {

        case PAM_PROMPT_ECHO_OFF:
          send_to_helper ("PAM_PROMPT_ECHO_OFF", msg[i]->msg);
          goto conv1;

        case PAM_PROMPT_ECHO_ON:
          send_to_helper ("PAM_PROMPT_ECHO_ON", msg[i]->msg);

        conv1:
          /* Wait for the agent's answer, but not only for it: the concurrent
           * stack winning means this prompt will never be answered, and
           * nothing else would ever wake us from it.
           */
          for (;;)
            {
              gboolean concurrent_ready = FALSE;
              int verdict_fd = conversation_data != NULL ? conversation_data->verdict_fd : -1;
              char verdict;

              if (read_line_from_agent (buf, sizeof buf, verdict_fd, &concurrent_ready) == 1)
                break;

              if (!concurrent_ready)
                goto error;

              /* Success there ends the request here. Failure only means this
               * prompt is once again the only way through, so stop watching
               * and keep waiting for the agent.
               */
              if (read (verdict_fd, &verdict, 1) == 1 && verdict == CONCURRENT_VERDICT_SUCCESS)
                {
                  conversation_data->concurrent_won = TRUE;
                  goto error;
                }

              close (verdict_fd);
              conversation_data->verdict_fd = -1;
            }

          aresp[i].resp = strdup (buf);
          if (aresp[i].resp == NULL)
            goto error;
          break;

        case PAM_ERROR_MSG:
          send_to_helper ("PAM_ERROR_MSG", msg[i]->msg);
          break;

        case PAM_TEXT_INFO:
          send_to_helper ("PAM_TEXT_INFO", msg[i]->msg);
          break;

        default:
          goto error;
        }
    }

  *resp = aresp;
  return PAM_SUCCESS;

error:

  for (i = 0; i < n; ++i)
    {
      if (aresp[i].resp != NULL) {
        memset (aresp[i].resp, 0, strlen(aresp[i].resp));
        free (aresp[i].resp);
      }
    }
  memset (aresp, 0, n * sizeof *aresp);
  free (aresp);
  *resp = NULL;
  return PAM_CONV_ERR;
}

/* Answers nothing. The concurrent stack has no one to ask -- the agent is
 * busy with the other conversation -- so a module that prompts is a
 * misconfiguration rather than something to paper over: the conversation
 * fails and that stack simply loses the race.
 */
static int
null_conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
  struct pam_response *aresp;
  int i;

  (void)data;
  if (n <= 0 || n > PAM_MAX_NUM_MSG)
    return PAM_CONV_ERR;

  if ((aresp = calloc (n, sizeof *aresp)) == NULL)
    return PAM_BUF_ERR;

  for (i = 0; i < n; ++i)
    {
      aresp[i].resp_retcode = 0;
      aresp[i].resp = NULL;

      switch (msg[i]->msg_style)
        {
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
          /* Dropped rather than forwarded: these belong to a conversation the
           * agent is not having, and interleaving them with the password
           * prompt's messages would mislead whoever is reading them.
           */
          break;

        default:
          free (aresp);
          *resp = NULL;
          return PAM_CONV_ERR;
        }
    }

  *resp = aresp;
  return PAM_SUCCESS;
}
