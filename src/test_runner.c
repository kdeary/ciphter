#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <windows.h>
#include "../lib/sds/sds.h"

volatile BOOL stop_tests = FALSE;
HANDLE hCurrentProcess = NULL;

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT) {
        stop_tests = TRUE;
        if (hCurrentProcess) {
            TerminateProcess(hCurrentProcess, 0);
        }
        return TRUE;
    }
    return FALSE;
}

// Custom function to run command and allow killing it early
int run_command_with_early_exit(const char *cmd, const char *expected, sds *captured_output) {
    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0)) return 0;
    if (!SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) return 0;

    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    BOOL bSuccess = FALSE;

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = hChildStd_OUT_Wr;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    bSuccess = CreateProcess(NULL, (char*)cmd, NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
    
    if (!bSuccess) {
        CloseHandle(hChildStd_OUT_Wr);
        CloseHandle(hChildStd_OUT_Rd);
        return 0;
    }

    hCurrentProcess = piProcInfo.hProcess;

    CloseHandle(hChildStd_OUT_Wr);

    DWORD dwRead;
    CHAR chBuf[4096];
    int found = 0;
    sds output_acc = sdsempty();

    while (TRUE) {
        bSuccess = ReadFile(hChildStd_OUT_Rd, chBuf, sizeof(chBuf) - 1, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;

        chBuf[dwRead] = '\0';
        output_acc = sdscat(output_acc, chBuf);

        if (strstr(output_acc, expected) != NULL) {
            found = 1;
            TerminateProcess(piProcInfo.hProcess, 0);
            break;
        }
    }

    WaitForSingleObject(piProcInfo.hProcess, INFINITE);

    if (captured_output) {
        *captured_output = sdsdup(output_acc);
    }

    sdsfree(output_acc);
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);
    CloseHandle(hChildStd_OUT_Rd);
    hCurrentProcess = NULL;

    return found;
}

void run_csv_test(const char *filename) {
    printf("[TEST] Running tests from: %s\n", filename);
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("[ERROR] Could not open %s\n", filename);
        return;
    }

    char line[16384];
    int line_num = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (stop_tests) break;
        line_num++;
        if (line_num == 1) continue; // Skip header

        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue;

        int count = 0;
        sds *tokens = sdssplitlen(line, strlen(line), ",", 1, &count);
        if (count < 5) {
            printf("[SKIP] Line %d: Invalid format\n", line_num);
            sdsfreesplitres(tokens, count);
            continue;
        }

        sds name = tokens[0];
        sds ciphertext = tokens[1];
        sds keys_str = tokens[2];
        sds crib = tokens[3];
        sds expected_plaintext = tokens[4];
        int depth = 1;
        if (count >= 6) depth = atoi(tokens[5]);

        printf("[RUN] %s (depth %d)... ", name, depth);
        fflush(stdout);

        sds cmd = sdsnew("bin/ciphter.exe -t S -s -T 5 "); 
        cmd = sdscatprintf(cmd, "-d %d ", depth);
        cmd = sdscatprintf(cmd, "-i \"%s\" ", ciphertext);
        
        if (sdslen(keys_str) > 0) {
            int k_count = 0;
            sds *k_tokens = sdssplitlen(keys_str, sdslen(keys_str), "|", 1, &k_count);
            for (int i = 0; i < k_count; i++) {
                if (sdslen(k_tokens[i]) > 0) cmd = sdscatprintf(cmd, "-k \"%s\" ", k_tokens[i]);
            }
            sdsfreesplitres(k_tokens, k_count);
        }

        if (sdslen(crib) > 0) {
            cmd = sdscatprintf(cmd, "-c \"%s\" ", crib);
        }

        sds captured = NULL;
        int pass = run_command_with_early_exit(cmd, expected_plaintext, &captured);

        if (pass) {
            printf("PASS\n");
        } else {
            printf("FAIL\n      Expected: %s\n", expected_plaintext);
            if (captured) {
                printf("      Actual Output:\n%s\n", captured);
            }
        }

        if (captured) sdsfree(captured);
        sdsfree(cmd);
        sdsfreesplitres(tokens, count);
    }
    fclose(fp);
}

int main() {
    DIR *d;
    struct dirent *dir;
    d = opendir("tests");
    if (d) {
        if (!SetConsoleCtrlHandler(HandlerRoutine, TRUE)) {
            printf("[ERROR] Could not set control handler\n");
            return 1;
        }
        while ((dir = readdir(d)) != NULL) {
            if (stop_tests) break;
            if (strstr(dir->d_name, ".csv") != NULL) {
                sds path = sdscatprintf(sdsempty(), "tests/%s", dir->d_name);
                run_csv_test(path);
                sdsfree(path);
            }
        }
        closedir(d);
    } else {
        printf("[ERROR] Could not open tests directory\n");
        return 1;
    }
    return 0;
}
