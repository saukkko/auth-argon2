#include "argon2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage()
{
    printf("Usage: auth-argon2 FILE1... FILE2... [OPTIONS]...\n");
    printf("  -h,  --help              print this help and exit\n");
    printf("       --version           print version information and exit (not implemented)\n");
    printf("  -q,  --quiet             suppress all messages (not implemented)\n");
    printf("  -v,  --verbose           verbose output (not implemented)\n");
    printf("\n");
    printf("If you encounter bugs, fix them.\n\n");

    exit(1);
}

long get_file_size(FILE *fp)
{
    long size;
    if (fseek(fp, 0L, SEEK_END) != 0)
    {
        fprintf(stderr, "fseek() failed\n");
        exit(1);
    }
    size = ftell(fp);
    rewind(fp);

    return size;
}

char* read_file(const char *filename)
{
    FILE *fp;
    long size;
    char *buf;

    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Error: opening file \"%s\" (does it exist?)\n", filename);
        exit(1);
    }

    size = get_file_size(fp);
    if (size < 1)
    {
        fprintf(stderr, "Error: Refusing to read empty file \"%s\"\n", filename);
        fclose(fp);
        exit(1);
    }

    buf = malloc(size+1);
    memset(buf, 0x00, size+1);

    uint64_t bytes_read = fread(buf, 1, size+5, fp);

    if (bytes_read == 0) {
        fprintf(stderr, "Error: File was empty when it shouldn't be\n");
        fclose(fp);
        exit(1);
    }

    if (bytes_read != size)
    {
        fprintf(stderr, "Error: Detected file size of %ld bytes_read but could read only %lu bytes. (is your EOL char LF or CRLF?)\n", size, bytes_read);
        fclose(fp);
        exit(1);
    }

    fclose(fp);

    return buf;
}

int main(int argc, char **argv)
{
#ifdef DEV
    fprintf(stderr, "Warning: You are running development build which is not intended for normal use.\n");
#endif
    if (argc > 4)
    {
        fprintf(stderr, "Error: Maximum number of arguments that make any sense is 3. Try --help or -h options.\n");
        exit(1);
    }
    char *help_str = "--help";
    char *h_str = "-h";

    for (int i = 0; i < argc; i++)
    {
        if ( strcmp(argv[i], help_str) == 0 || strcmp(argv[i], h_str) == 0 )
        {
            print_usage();
            return 1;
        }
    }

    char *filename1;
    char *filename2;

    if (argc < 3)
    {
#ifdef DEV
        /* NOTE: Hard coded filenames are provided here, if we are running DEV build and either isn't provided */
        filename1 = malloc(10);
        memset(filename1, 0x00, 10);
        strcpy(filename1, "creds.txt");
        printf("*** Using %s as file1\n", filename1);

        filename2 = malloc(10);
        memset(filename2, 0x00, 10);
        strcpy(filename2, "login.txt");
        printf("*** Using %s as file2\n", filename2);
#else
        fprintf(stderr, "Error: Need 2 arguments but only %d provided.\n", argc-1);
        return 1;
#endif
    } else
    {
        filename1 = argv[1];
        filename2 = argv[2];
    }

    /*
     * This section is pretty straightforward. It reads file given as arg2 and
     * parses the first two rows.
     * Row 1: username
     * Row 2: plaintext password
     */
    /** parse login data **/
    char *login_data = read_file(filename2);
    int login_len = (int) strlen(login_data);

    char login[login_len + 1];
    strcpy(login, login_data);

    char *search_username;
    char *plaintext;
    char *ptr;

    ptr = strtok(login, "\n");
    if (ptr == NULL) {
        fprintf(stderr, "Error: File \"%s\" contains rows but has no contents.\n", filename2);
        return 1;
    }

    search_username = ptr;

    ptr = strtok(NULL, "\n");
    if (ptr == NULL)
    {
        fprintf(stderr, "Error: File \"%s\" only has one data row but we need two.\n", filename2);
        return 1;
    }
    plaintext = ptr;
    ptr = NULL;

    int plaintext_len = (int) strlen(plaintext);


    /** parse credentials file stored in local machine **/
    char *credential_data = read_file(filename1);
    uint64_t data_len = strlen(credential_data);

    char credentials[data_len + 1];
    strcpy(credentials, credential_data);

    int rowcount = 1; // 0 rows really don't work so init to 1 here
    for (int i = 0; i < data_len; i++)
    {
        if (strncmp(credential_data++, "\n", 1) == 0)
            rowcount++;
    }

    char *rows[rowcount];
    char *username = NULL;
    char *enc = NULL;


    // TODO: these two loops could be improved.
    ptr = strtok(credentials, "\n");
    int i=0;
    while (rowcount--) {
        rows[i] = ptr;
        i++;
        ptr = strtok(NULL, "\n");
    }
    ptr = NULL;
    while (i--)
    {
        ptr = strtok(rows[i], ":");

        if (ptr == NULL)
        {
            fprintf(stderr, "Warning: Encountered empty row, ignoring it...\n");
            continue;
        }

        /** find the correct user and and retrieve encoded salt and hash **/
        if (strcmp(ptr, search_username) == 0)
        {
            username = ptr;
            ptr = strtok(NULL, ":");
            enc = ptr;
            break;
        }
    }

    if (username == NULL || enc == NULL)
    {
        fprintf(stderr, "Error: User not found.\n");
        exit(1);
    }

    /** verify the hash by re-calculating the hash with provided plaintext and
     * compare them to those stored in local machine **/
    FILE *stream = stdout;
    int verify_result = argon2i_verify(enc, plaintext, plaintext_len);
    if (verify_result != ARGON2_OK)
        stream = stderr;
    fprintf(stream, "Verifying \"%s\": %s\n", username, argon2_error_message(verify_result));

    if (verify_result == ARGON2_OK)
    {
        return 0;
    }

    return 1;
}
