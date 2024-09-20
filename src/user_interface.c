#include "file_protection.h"

void print_help()
{
    printf("\n=== File Protection System ===\n");
    printf("Available commands:\n");
    printf("  help    - Show this help message\n");
    printf("  enable  - Enable file protection\n");
    printf("  disable - Disable file protection (requires password)\n");
    printf("  change  - Change password\n");
    printf("  status  - Show current protection status\n");
    printf("  stop    - Stop the program\n");
    printf("==============================\n\n");
}

// Function to check if the provided password matches the stored hash
int check_password(const char *password)
{
    FILE *file = fopen(TEMPLATE_FILE, "r");
    if (file == NULL)
    {
        log_message("Error opening template file for password check");
        return -1;
    }

    char stored_hash[256];
    if (fgets(stored_hash, sizeof(stored_hash), file) == NULL)
    {
        fclose(file);
        return -1;
    }
    fclose(file);

    stored_hash[strcspn(stored_hash, "\n")] = 0; // Remove newline

    char salt[13];
    strncpy(salt, stored_hash, 12);
    salt[12] = '\0';

    char *computed_hash = crypt(password, salt);
    return strcmp(computed_hash, stored_hash) == 0;
}

// Function to change the password
int change_password(const char *old_password, const char *new_password)
{
    if (!check_password(old_password))
    {
        return -1; // Old password is incorrect
    }

    FILE *file = fopen(TEMPLATE_FILE, "r+");
    if (file == NULL)
    {
        log_message("Error opening template file for password change");
        return -1;
    }

    char salt[13];
    strncpy(salt, "0123456789ab", 12);
    salt[12] = '\0';

    char *new_hash = crypt(new_password, salt);

    // Write the new hash to the file
    rewind(file);
    fprintf(file, "%s\n", new_hash);

    fclose(file);
    return 0;
}

void handle_user_input()
{
    char cmd[20];
    if (fgets(cmd, sizeof(cmd), stdin))
    {
        cmd[strcspn(cmd, "\n")] = 0; // Remove newline
        if (strcmp(cmd, "help") == 0)
        {
            print_help();
        }
        else if (strcmp(cmd, "enable") == 0)
        {
            protection_enabled = 1;
            printf("Protection enabled.\n");
            log_message("Protection enabled");
        }
        else if (strcmp(cmd, "disable") == 0)
        {
            if (authenticate_user())
            {
                disable_protection();
            }
        }
        else if (strcmp(cmd, "change") == 0)
        {
            change_password_interactive();
        }
        else if (strcmp(cmd, "status") == 0)
        {
            print_status();
        }
        else if (strcmp(cmd, "stop") == 0)
        {
            printf("Stopping file protection system...\n");
            log_message("Stopping file protection system");
            exit(0);
        }
        else
        {
            printf("Unknown command. Type 'help' for available commands.\n");
            char log_buf[MAX_PATH_LEN + 100];
            create_log_buffer(log_buf, sizeof(log_buf), "Unknown command entered: %s", cmd);
            log_message(log_buf);
        }
    }
}

// Function to authenticate the user
int authenticate_user()
{
    char password[256];
    printf("Enter password: ");
    if (fgets(password, sizeof(password), stdin))
    {
        password[strcspn(password, "\n")] = 0; // Remove newline
        if (check_password(password))
        {
            return 1;
        }
        else
        {
            printf("Incorrect password.\n");
            log_message("Attempt to disable protection with incorrect password");
            return 0;
        }
    }
    return 0;
}

// Function to change password interactively
void change_password_interactive()
{
    char old_password[256], new_password[256];
    printf("Enter old password: ");
    if (fgets(old_password, sizeof(old_password), stdin))
    {
        old_password[strcspn(old_password, "\n")] = 0;
        printf("Enter new password: ");
        if (fgets(new_password, sizeof(new_password), stdin))
        {
            new_password[strcspn(new_password, "\n")] = 0;
            if (change_password(old_password, new_password) == 0)
            {
                printf("Password changed successfully.\n");
                log_message("Password changed successfully");
            }
            else
            {
                printf("Failed to change password. Make sure the old password is correct.\n");
                log_message("Failed attempt to change password");
            }
        }
    }
}

// Function to print the current status of the protection system
void print_status()
{
    printf("Protection status: %s\n", protection_enabled ? "Enabled" : "Disabled");
    printf("Protected directory: %s\n", protected_directory);
    char log_buf[MAX_PATH_LEN + 100];
    create_log_buffer(log_buf, sizeof(log_buf), "Status checked. Protection: %s", protection_enabled ? "Enabled" : "Disabled");
    log_message(log_buf);
}

// Function to disable protection and restore file permissions
void disable_protection()
{
    protection_enabled = 0;
    printf("Protection disabled.\n");
    log_message("Protection disabled");

    DIR *dir;
    struct dirent *entry;

    dir = opendir(protected_directory);
    if (dir == NULL)
    {
        log_message("Failed to open protected directory for restoring permissions");
        return;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_REG)
        {
            char full_path[PATH_MAX];
            int path_len = snprintf(full_path, sizeof(full_path), "%s/%s", protected_directory, entry->d_name);
            if (path_len < 0 || path_len >= (int)sizeof(full_path))
            {
                char log_buf[MAX_PATH_LEN + 100];
                snprintf(log_buf, sizeof(log_buf), "Path too long for file: %s", entry->d_name);
                log_message(log_buf);
                continue;
            }

            clear_immutable_flag(full_path);

            if (chmod(full_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != 0)
            {
                char log_buf[MAX_PATH_LEN + 100];
                snprintf(log_buf, sizeof(log_buf), "Failed to restore permissions for: %s", full_path);
                log_message(log_buf);
            }
        }
    }

    closedir(dir);
}
