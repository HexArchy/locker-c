#include "file_protection.h"

char *templates[MAX_TEMPLATES];
int template_count = 0;
int protection_enabled = 0;
char protected_directory[MAX_PATH_LEN] = {0};

void log_message(const char *message)
{
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL)
    {
        perror("Error opening log file");
        return;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline
    fprintf(log_file, "[%s] %s\n", time_str, message);
    fclose(log_file);
}

// Function to load templates and protected directory from the template file
int load_templates()
{
    log_message("Loading templates");
    FILE *file = fopen(TEMPLATE_FILE, "r");
    if (file == NULL)
    {
        log_message("Error opening template file");
        return -1;
    }

    char line[MAX_FILENAME_LEN];
    int line_count = 0;
    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = 0; // Remove newline
        if (line_count == 0)
        {
            // Skip the first line (hashed password)
            line_count++;
            continue;
        }
        if (line_count == 1)
        {
            // Resolve and set the absolute path of the protected directory
            char *resolved_path = realpath(line, NULL);
            if (resolved_path == NULL)
            {
                log_message("Error resolving protected directory path");
                fclose(file);
                return -1;
            }
            strncpy(protected_directory, resolved_path, MAX_PATH_LEN - 1);
            protected_directory[MAX_PATH_LEN - 1] = '\0';
            free(resolved_path);

            char log_buf[MAX_PATH_LEN + 50];
            snprintf(log_buf, sizeof(log_buf), "Protected directory set to: %s", protected_directory);
            log_message(log_buf);
            line_count++;
            continue;
        }
        // Load template patterns
        templates[template_count] = strdup(line);
        char log_buf[MAX_FILENAME_LEN + 30];
        snprintf(log_buf, sizeof(log_buf), "Loaded template: %s", templates[template_count]);
        log_message(log_buf);
        template_count++;
        line_count++;
        if (template_count >= MAX_TEMPLATES)
            break;
    }

    fclose(file);
    log_message("Templates loaded successfully");
    return 0;
}

// Function to check if a directory is a subdirectory of another
int is_subdirectory(const char *parent, const char *sub)
{
    char parent_real[MAX_PATH_LEN];
    char sub_real[MAX_PATH_LEN];

    if (realpath(parent, parent_real) == NULL || realpath(sub, sub_real) == NULL)
    {
        return 0;
    }

    size_t parent_len = strlen(parent_real);
    return strncmp(parent_real, sub_real, parent_len) == 0 &&
           (sub_real[parent_len] == '/' || sub_real[parent_len] == '\0');
}

// Function to check if a file is protected based on its name and location
int is_protected(const char *filename)
{
    // Don't protect the log file
    if (strcmp(basename((char *)filename), LOG_FILE) == 0)
    {
        return 0;
    }

    char *file_copy = strdup(filename);
    if (file_copy == NULL)
    {
        log_message("Memory allocation failed in is_protected");
        return 0;
    }

    char *dir_name = dirname(file_copy);
    if (!is_subdirectory(protected_directory, dir_name))
    {
        free(file_copy);
        return 0;
    }

    char *base_name = basename(file_copy);
    int is_prot = 0;
    for (int i = 0; i < template_count; i++)
    {
        if (fnmatch(templates[i], base_name, 0) == 0)
        {
            is_prot = 1;
            break;
        }
    }

    free(file_copy);
    return is_prot;
}

// Function to handle file system events
void handle_event(struct inotify_event *event)
{
    if (event->len && protection_enabled)
    {
        if (strcmp(event->name, LOG_FILE) == 0)
        {
            return;
        }

        char full_path[PATH_MAX];
        int path_len = snprintf(full_path, sizeof(full_path), "%s/%s", protected_directory, event->name);
        if (path_len < 0 || path_len >= (int)sizeof(full_path))
        {
            char log_buf[MAX_PATH_LEN + 100];
            snprintf(log_buf, sizeof(log_buf), "Path too long for file: %s", event->name);
            log_message(log_buf);
            return;
        }

        if (is_protected(full_path))
        {
            char log_buf[MAX_PATH_LEN + 100];
            // Handle different types of events (create, delete, move, modify)
            if (event->mask & IN_CREATE)
            {
                // Block creation of protected files
                if (unlink(full_path) == 0)
                {
                    snprintf(log_buf, sizeof(log_buf), "Blocked creation of protected file: %s", full_path);
                    log_message(log_buf);
                    printf("Blocked creation of protected file: %s\n", full_path);
                }
                else
                {
                    snprintf(log_buf, sizeof(log_buf), "Failed to block creation of protected file: %s", full_path);
                    log_message(log_buf);
                }
            }
            else if (event->mask & IN_DELETE)
            {
                // Restore deleted protected files
                FILE *file = fopen(full_path, "a");
                if (file != NULL)
                {
                    fclose(file);
                    protect_file(full_path);
                    snprintf(log_buf, sizeof(log_buf), "Blocked deletion of protected file: %s", full_path);
                    log_message(log_buf);
                    printf("Blocked deletion of protected file: %s\n", full_path);
                }
                else
                {
                    snprintf(log_buf, sizeof(log_buf), "Failed to restore protected file: %s", full_path);
                    log_message(log_buf);
                }
            }
            else if (event->mask & IN_MOVED_FROM || event->mask & IN_MOVED_TO)
            {
                // Block move operations on protected files
                FILE *file = fopen(full_path, "a");
                if (file != NULL)
                {
                    fclose(file);
                    protect_file(full_path);
                    snprintf(log_buf, sizeof(log_buf), "Blocked move operation on protected file: %s", full_path);
                    log_message(log_buf);
                    printf("Blocked move operation on protected file: %s\n", full_path);
                }
                else
                {
                    snprintf(log_buf, sizeof(log_buf), "Failed to restore moved protected file: %s", full_path);
                    log_message(log_buf);
                }
            }
            else if (event->mask & IN_MODIFY)
            {
                // Block modifications to protected files
                protect_file(full_path);
                snprintf(log_buf, sizeof(log_buf), "Blocked modification of protected file: %s", full_path);
                log_message(log_buf);
                printf("Blocked modification of protected file: %s\n", full_path);
            }
        }
    }
}

// Function to protect a file by setting it as immutable and read-only
void protect_file(const char *path)
{
    // Set the immutable attribute
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to open file for protection: %s", path);
        log_message(log_buf);
        return;
    }

    unsigned long flags;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to get flags for file: %s", path);
        log_message(log_buf);
        close(fd);
        return;
    }

    flags |= FS_IMMUTABLE_FL;

    if (ioctl(fd, FS_IOC_SETFLAGS, &flags) < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to set immutable flag for file: %s", path);
        log_message(log_buf);
    }

    close(fd);

    // Set read-only permissions
    if (chmod(path, S_IRUSR | S_IRGRP | S_IROTH) < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to set read-only permissions for file: %s", path);
        log_message(log_buf);
    }
}

// Function to set the immutable flag on a file
void set_immutable(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to open file for setting immutable attribute: %s", path);
        log_message(log_buf);
        return;
    }

    unsigned long flags;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to get flags for file: %s", path);
        log_message(log_buf);
        close(fd);
        return;
    }

    flags |= FS_IMMUTABLE_FL;

    if (ioctl(fd, FS_IOC_SETFLAGS, &flags) < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to set immutable flag for file: %s", path);
        log_message(log_buf);
    }
    else
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Set immutable flag for file: %s", path);
        log_message(log_buf);
    }

    close(fd);
}

// Function to clear the immutable flag from a file
void clear_immutable_flag(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to open file for clearing immutable flag: %s", path);
        log_message(log_buf);
        return;
    }

    unsigned long flags;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to get flags for file: %s", path);
        log_message(log_buf);
        close(fd);
        return;
    }

    // Clear the immutable flag
    flags &= ~FS_IMMUTABLE_FL;

    if (ioctl(fd, FS_IOC_SETFLAGS, &flags) < 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Failed to clear immutable flag for file: %s", path);
        log_message(log_buf);
    }
    else
    {
        char log_buf[MAX_PATH_LEN + 100];
        snprintf(log_buf, sizeof(log_buf), "Cleared immutable flag for file: %s", path);
        log_message(log_buf);
    }

    close(fd);
}

// Function to restore write permissions to a file
void restore_permissions(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (chmod(path, st.st_mode | S_IWUSR | S_IWGRP | S_IWOTH) != 0)
        {
            char log_buf[MAX_PATH_LEN + 100];
            snprintf(log_buf, sizeof(log_buf), "Failed to restore permissions for: %s", path);
            log_message(log_buf);
        }
    }
}

void create_log_buffer(char *buffer, size_t buffer_size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, buffer_size, format, args);
    va_end(args);
}

FILE *safe_fopen(const char *path, const char *mode)
{
    FILE *file = fopen(path, mode);
    if (file == NULL)
    {
        char log_buf[MAX_PATH_LEN + 100];
        create_log_buffer(log_buf, sizeof(log_buf), "Failed to open file: %s", path);
        log_message(log_buf);
    }
    return file;
}

void safe_fclose(FILE *file, const char *path)
{
    if (fclose(file) != 0)
    {
        char log_buf[MAX_PATH_LEN + 100];
        create_log_buffer(log_buf, sizeof(log_buf), "Failed to close file: %s", path);
        log_message(log_buf);
    }
}