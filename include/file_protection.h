#ifndef FILE_PROTECTION_H
#define FILE_PROTECTION_H

#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <limits.h>
#include <crypt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <fnmatch.h>
#include <time.h>
#include <dirent.h>
#include <libgen.h>
#include <stdarg.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))
#define TEMPLATE_FILE "template.tbl"
#define MAX_FILENAME_LEN 256
#define MAX_TEMPLATES 100
#define LOG_FILE "file_protection.log"
#define MAX_PATH_LEN 4096
#define MAX_WATCHES 1000

extern char *templates[MAX_TEMPLATES];
extern int template_count;
extern int protection_enabled;
extern char protected_directory[MAX_PATH_LEN];

// File operations
void log_message(const char *message);
int load_templates();
int is_subdirectory(const char *parent, const char *sub);
int is_protected(const char *filename);
void handle_event(int fd, struct inotify_event *event);
void protect_file(const char *path);
void set_immutable(const char *path);
void clear_immutable_flag(const char *path);
void restore_permissions(const char *path);
void create_log_buffer(char *buffer, size_t buffer_size, const char *format, ...);
FILE *safe_fopen(const char *path, const char *mode);
void safe_fclose(FILE *file, const char *path);
void add_watch_recursive(int fd, const char *path);

// User interface
void print_help();
int check_password(const char *password);
int change_password(const char *old_password, const char *new_password);
void handle_user_input();
int authenticate_user();
void change_password_interactive();
void print_status();
void disable_protection();
void remove_protection_recursive(const char *path);

// System initialization and cleanup
int initialize_protection_system();
void cleanup_protection_system();
int run_protection_system();
void handle_file_events(int fd, char *buffer);

#endif