/*
   Copyright 2012,2013,2014 Open Source Security, Inc.
   All Rights Reserved
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/xattr.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <syslog.h>
#include <limits.h>
#include <signal.h>

#define MAX_CONFIG_ENTRIES 16384

#define INOTIFY_FLAGS (IN_DONT_FOLLOW | IN_ATTRIB | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF | IN_MOVED_TO)
#define PARENT_INOTIFY_FLAGS (INOTIFY_FLAGS &~ IN_ATTRIB)

#define PAX_PAGEEXEC_ON  0x00000001
#define PAX_SEGMEXEC_ON  0x00000002
#define PAX_MPROTECT_ON  0x00000004
#define PAX_ASLR_ON      0x00000008
#define PAX_EMUTRAMP_ON  0x00000010

#define PAX_PAGEEXEC_OFF 0x00010000
#define PAX_SEGMEXEC_OFF 0x00020000
#define PAX_MPROTECT_OFF 0x00040000
#define PAX_ASLR_OFF     0x00080000
#define PAX_EMUTRAMP_OFF 0x00100000

struct conf_entry {
	char *requested_path;
	char *existing_path;
	char *pax_flags_str;
	unsigned int pax_flags;
	int watch_id;
	int setxattr;
	int nonroot;
};

struct paxctld_config {
	struct conf_entry *entries;
	unsigned int count;
};

static struct paxctld_config config;
static int ino;

static int do_daemonize;
static char *pidfile;

static int quiet;
#define gr_syslog(level, ...) do {				\
	if (!quiet) {						\
		if (do_daemonize)				\
			syslog(level, ## __VA_ARGS__);		\
		else						\
			fprintf(stderr, ## __VA_ARGS__);	\
	}							\
} while (0)

/*
static char *mask_to_string(char *buf, unsigned int mask)
{
	unsigned int flags[] = {
		IN_ACCESS,
		IN_ATTRIB,
		IN_CLOSE_WRITE,
		IN_CLOSE_NOWRITE,
		IN_CREATE,
		IN_DELETE,
		IN_DELETE_SELF,
		IN_MODIFY,
		IN_MOVE_SELF,
		IN_MOVED_FROM,
		IN_MOVED_TO,
		IN_OPEN
	};
	const char *flagnames[] = {
		"access",
		"attrib",
		"close_write",
		"close_nowrite",
		"create",
		"delete",
		"delete_self",
		"modify",
		"move_self",
		"moved_from",
		"moved_to",
		"open"
	};
	int i;

	buf[0] = '\0';

	for (i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
		if (mask & flags[i]) {
			strcat(buf, flagnames[i]);
			strcat(buf, " ");
		}
	}
	return buf;
}
*/


static char *gr_strdup(const char *str)
{
	char *ret = strdup(str);
	if (ret == NULL) {
		fprintf(stderr, "Unable to allocate memory.\n");
		exit(EXIT_FAILURE);
	}	return ret;
}

static unsigned int encode_pax_flags(const char *conf)
{
	unsigned int ret = 0;
	const char *p = conf;
	while (*p) {
		switch (*p) {
		case 'P':
			ret |= PAX_PAGEEXEC_ON;
			break;
		case 'p':
			ret |= PAX_PAGEEXEC_OFF;
			break;
		case 'E':
			ret |= PAX_EMUTRAMP_ON;
			break;
		case 'e':
			ret |= PAX_EMUTRAMP_OFF;
			break;
		case 'M':
			ret |= PAX_MPROTECT_ON;
			break;
		case 'm':
			ret |= PAX_MPROTECT_OFF;
			break;
		case 'R':
			ret |= PAX_ASLR_ON;
			break;
		case 'r':
			ret |= PAX_ASLR_OFF;
			break;
		case 'S':
			ret |= PAX_SEGMEXEC_ON;
			break;
		case 's':
			ret |= PAX_SEGMEXEC_OFF;
			break;
		default:
			fprintf(stderr, "Unknown character: \"%c\" in PaX configuration string: \"%s\".  Permitted characters are: \"PpEeMmRrSs\".\n", *p, conf);
			exit(EXIT_FAILURE);
		}
		p++;
	};

	if ((ret >> 16) & (ret & 0xFFFF)) {
		fprintf(stderr, "PaX config string: \"%s\" tries to both enable and disable a PaX feature.  Please review configuration file.\n", conf);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static char *get_parent_dir(char *path)
{
	char *tmpp = strrchr(path, '/');
	if (tmpp) {
		if (tmpp == path)
			tmpp[1] = '\0';
		else
			tmpp[0] = '\0';
	}

	return path;
}

/* do safe setting of user xattrs */
static int set_xattr(const struct conf_entry *entry)
{
	struct stat st;
	uid_t linkuid;
	char path[PATH_MAX+1];
	int ret;

	if (lstat(entry->requested_path, &st)) {
		if (errno == ENOENT)
			return 0;
		goto error;
	}

	linkuid = st.st_uid;
	if (!entry->nonroot && linkuid)
		goto error2;

	if (!realpath(entry->requested_path, path))
		return 0;

	if (lstat(path, &st)) {
		if (errno == ENOENT)
			return 0;
		goto error;
	}

	if (entry->nonroot && st.st_uid != linkuid && linkuid)
		goto error2;

	// create or replace as necessary
	ret = lsetxattr(path, "user.pax.flags", entry->pax_flags_str, strlen(entry->pax_flags_str), 0);
	if (ret == -1) {
		if (errno == ENOENT)
			return 0;
		goto error;
	}

	return 1;
error:
	gr_syslog(LOG_ERR, "Unable to set extended attribute on \"%s\".  Error: %s\n", entry->requested_path, strerror(errno));
	exit(EXIT_FAILURE);
error2:
	gr_syslog(LOG_ERR, "Unable to set extended attribute on \"%s\".  Error: owner of symlink did not match that of target.\n", entry->requested_path);
	exit(EXIT_FAILURE);
}

static char *append_path(char *path, char *last)
{
	char *ret = calloc(1, strlen(path) + strlen(last) + 2);
	if (ret == NULL) {
		fprintf(stderr, "Unable to allocate memory.\n");
		exit(EXIT_FAILURE);
	}

	if (strcmp(path, "/"))
		sprintf(ret, "%s/%s", path, last);
	else
		sprintf(ret, "/%s", last);

	return ret;
}

static void parse_config(const char *confpath, struct paxctld_config *config)
{
	FILE *f = fopen(confpath, "r");
	char buf[8192] = { 0 };
	char *p;
	char path[4096] = { 0 };
	char flags[16] = { 0 };
	unsigned long lineno = 0;
	int nonroot;
	int ret;

	if (f == NULL) {
		fprintf(stderr, "Unable to open configuration file: %s\nError: %s\n", confpath, strerror(errno));
		exit(EXIT_FAILURE);
	}

	config->count = 0;
	config->entries = calloc(MAX_CONFIG_ENTRIES, sizeof(struct conf_entry));
	if (config->entries == NULL) {
		fprintf(stderr, "Unable to allocate memory.\n");
		exit(EXIT_FAILURE);
	}

	while(fgets(buf, sizeof(buf) - 1, f)) {
		lineno++;

		p = buf;
		while (*p == ' ' || *p == '\t')
			p++;
		// ignore comment and empty lines
		if (*p == '#' || *p == '\n')
			continue;
		ret = sscanf(p, "%4095s %15s nonroot", path, flags);
		if (ret != 2) {
			nonroot = 0;
			ret = sscanf(p, "%4095s %15s", path, flags);
		} else {
			nonroot = 1;
		}
		if (ret != 2) {
			fprintf(stderr, "Invalid configuration on line %lu of %s.\nSyntax is: </absolute/path> <PaX flags> [nonroot]\n", lineno, confpath);
			exit(EXIT_FAILURE);
		}

		config->entries[config->count].nonroot = nonroot;
		config->entries[config->count].requested_path = gr_strdup(path);
		config->entries[config->count].pax_flags = encode_pax_flags(flags);
		config->entries[config->count].pax_flags_str = gr_strdup(flags);

		set_xattr(&config->entries[config->count]);

		config->count++;
	}

	fclose(f);
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s [-c config_file] [-d] [-p pid_file] [-q]\n", name);
	exit(EXIT_FAILURE);
}

static int file_monitored(const char *path)
{
	unsigned int i;
	for (i = 0; i < config.count; i++) {
		struct conf_entry *entry = &config.entries[i];
		if (!strcmp(entry->existing_path, path))
			return 1;
	}
	return 0;
}

static void handle_event(struct inotify_event *event, struct conf_entry *confentry)
{
	if ((event->mask & (IN_CREATE | IN_MOVED_TO)) && strcmp(confentry->existing_path, confentry->requested_path) &&
	    !file_monitored(confentry->requested_path)) {
		char *p = append_path(confentry->existing_path, event->name);
		confentry->watch_id = inotify_add_watch(ino, p, INOTIFY_FLAGS);
		free(confentry->existing_path);
		confentry->existing_path = p;
		gr_syslog(LOG_INFO, "File %s created.\n", confentry->existing_path);
	} else if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
		gr_syslog(LOG_INFO, "File %s deleted.\n", confentry->existing_path);
		get_parent_dir(confentry->existing_path);
		confentry->watch_id = inotify_add_watch(ino, confentry->existing_path, PARENT_INOTIFY_FLAGS);
	} else if ((event->mask & IN_ATTRIB) && !strcmp(confentry->existing_path, confentry->requested_path)) {
		struct stat st;
		/* if we just set the extended attributes, then ignore this event and reset our trigger */
		if (confentry->setxattr) {
			confentry->setxattr = 0;
			return;
		}
		if ((lstat(confentry->existing_path, &st)) == -1 && errno == ENOENT) {
			// file was deleted
			gr_syslog(LOG_INFO, "File %s deleted.\n", confentry->existing_path);
			get_parent_dir(confentry->existing_path);
			confentry->watch_id = inotify_add_watch(ino, confentry->existing_path, PARENT_INOTIFY_FLAGS);
		} else {
			gr_syslog(LOG_INFO, "File %s had its attributes changed.\n", confentry->existing_path);
		}
	}
	/* if after processing the existing file matches the requested file, then set
	   extended attributes on the file */
	if (!strcmp(confentry->existing_path, confentry->requested_path)) {
		// create or replace as necessary
		int ret = set_xattr(confentry);
		if (ret) {
			confentry->setxattr = 1;
			gr_syslog(LOG_INFO, "Restored PaX flags on \"%s\" after update.\n", confentry->existing_path);
		}
	}
}

static void daemonize(void)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		if (setsid() < 0)
			exit(EXIT_FAILURE);
		signal(SIGCHLD, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
		pid = fork();
		if (pid == 0) {
			FILE *f;
			int i;
			if (chdir("/"))
				exit(EXIT_FAILURE);
			for (i = 0; i <= sysconf(_SC_OPEN_MAX); i++)
				if (i != ino)
					close(i);
			if (pidfile) {
				f = fopen(pidfile, "w");
				fprintf(f, "%u\n", getpid());
				fclose(f);
			}

			openlog("paxctld", 0, LOG_DAEMON);

			return;
		} else
			exit(EXIT_SUCCESS);
	} else
		exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int opt;
	char *config_path = "/etc/paxctld.conf";
	unsigned int i;
	struct inotify_event *event;
	char flags[16] = { 0 };

	if (argc < 1)
		usage("paxctld");

	while ((opt = getopt(argc, argv, "c:dp:q")) != -1) {
		switch (opt) {
		case 'c':
			config_path = gr_strdup(optarg);
			break;
		case 'd':
			do_daemonize = 1;
			break;
		case 'p':
			pidfile = gr_strdup(optarg);
			break;
		case 'q':
			quiet = 1;
			break;
		default:
			fprintf(stderr, "Unknown option: \"%c\".", opt);
			usage(argv[0]);
		}
	}

	if (getxattr("/proc/self/exe", "user.pax.flags", flags, sizeof(flags)-1) == -1 && errno == ENOTSUP) {
		fprintf(stderr, "Fatal: Filesystem extended attribute support is not enabled on the current running kernel.\n");
		exit(EXIT_FAILURE);
	}

	parse_config(config_path, &config);

	ino = inotify_init();
	if (ino < 0) {
		fprintf(stderr, "Fatal: Unable to initialize inotify system: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	event = calloc(1, sizeof(struct inotify_event) + 4096);
	if (event == NULL) {
		fprintf(stderr, "Fatal: Unable to allocate memory.\n");
		exit(EXIT_FAILURE);
	}

	if (do_daemonize)
		daemonize();

	gr_syslog(LOG_INFO, "paxctld initialized.\n");

	for (i = 0; i < config.count; i++) {
		char tmp[4096];
		struct conf_entry *entry = &config.entries[i];
		strncpy(tmp, entry->requested_path, sizeof(tmp));
		int id = inotify_add_watch(ino, entry->requested_path, INOTIFY_FLAGS);
		while (id == -1 && errno == ENOENT && strcmp(tmp, "/")) {
			// keep stripping path components until we reach an existing directory
			get_parent_dir(tmp);
			id = inotify_add_watch(ino, tmp, PARENT_INOTIFY_FLAGS);
		}
		entry->watch_id = id;
		entry->existing_path = gr_strdup(tmp);
	}

	while (read(ino, event, sizeof(struct inotify_event) + 4096) > 0) {
		// if it's a delete, we need to remove the watch on the file and add it to its parent directory
		for (i = 0; i < config.count; i++) {
			//char maskname[128];
			struct conf_entry *entry = &config.entries[i];
			if (event->wd != entry->watch_id)
				continue;
			//printf("Event mask: %s\n", mask_to_string(maskname, event->mask));
			handle_event(event, entry);
		}
	}

	return 0;
}
