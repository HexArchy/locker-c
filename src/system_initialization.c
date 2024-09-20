#include "file_protection.h"

int initialize_protection_system()
{
    log_message("Initializing file protection system");

    if (load_templates() < 0)
    {
        log_message("Failed to load templates. Exiting.");
        return -1;
    }

    struct stat st;
    if (stat(protected_directory, &st) == -1)
    {
        char log_buf[MAX_PATH_LEN + 100];
        create_log_buffer(log_buf, sizeof(log_buf), "Protected directory does not exist or is inaccessible: %s", protected_directory);
        log_message(log_buf);
        return -1;
    }

    log_message("File protection system initialized successfully");
    return 0;
}

void cleanup_protection_system()
{
    log_message("Cleaning up file protection system");

    for (int i = 0; i < template_count; i++)
    {
        free(templates[i]);
    }

    if (protection_enabled)
    {
        disable_protection();
    }

    log_message("File protection system cleanup completed");
}

int run_protection_system()
{
    int fd, wd;
    char buffer[EVENT_BUF_LEN];

    if (initialize_protection_system() < 0)
    {
        return 1;
    }

    fd = inotify_init();
    if (fd < 0)
    {
        log_message("Failed to initialize inotify");
        perror("inotify_init");
        return 1;
    }

    wd = inotify_add_watch(fd, protected_directory, IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MODIFY);
    if (wd < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        create_log_buffer(log_buf, sizeof(log_buf), "Failed to add inotify watch for %s: %s", protected_directory, strerror(errno));
        log_message(log_buf);
        close(fd);
        return 1;
    }

    printf("File protection system started.\n");
    printf("Protected directory: %s\n", protected_directory);
    print_help();

    while (1)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(fd, &fds);

        int ret = select(fd + 1, &fds, NULL, NULL, NULL);
        if (ret < 0)
        {
            perror("select");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &fds))
        {
            handle_user_input();
        }

        if (FD_ISSET(fd, &fds))
        {
            handle_file_events(fd, buffer);
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    cleanup_protection_system();

    printf("File protection system stopped.\n");
    return 0;
}

void handle_file_events(int fd, char *buffer)
{
    int length = read(fd, buffer, EVENT_BUF_LEN);
    if (length < 0)
    {
        log_message("Error reading inotify events");
        perror("read");
        return;
    }

    int i = 0;
    while (i < length)
    {
        struct inotify_event *event = (struct inotify_event *)&buffer[i];
        handle_event(event);
        i += EVENT_SIZE + event->len;
    }
}