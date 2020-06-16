/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Baldur Karlsson
 * Copyright (c) 2014 Crytek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

#include "renderdoccmd.h"
#include <app/renderdoc_app.h>
#include <renderdocshim.h>
#include <windows.h>
#include <string>
#include <vector>
#include "miniz/miniz.h"
#include "control_types.h"
#include "rdcstr.h"
#include "renderdoc_replay.h"
#include "resource.h"

#include <Psapi.h>
#include <tlhelp32.h>
#include <time.h>

#include <atomic>         
#include <thread>

static std::string conv(const std::wstring &str)
{
  std::string ret;
  // worst case each char takes 4 bytes to encode
  ret.resize(str.size() * 4 + 1);

  WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, &ret[0], (int)ret.size(), NULL, NULL);

  ret.resize(strlen(ret.c_str()));

  return ret;
}

static std::wstring conv(const std::string &str)
{
  std::wstring ret;
  ret.resize(str.size() + 1);

  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &ret[0], int(ret.size() + 1));

  ret.resize(wcslen(ret.c_str()));

  return ret;
}

HINSTANCE hInstance = NULL;

#if defined(RELEASE) && RENDERDOC_OFFICIAL_BUILD
#define CRASH_HANDLER 1
#else
#define CRASH_HANDLER 0
#endif

#if CRASH_HANDLER
// breakpad
#include "breakpad/client/windows/crash_generation/client_info.h"
#include "breakpad/client/windows/crash_generation/crash_generation_server.h"
#include "breakpad/common/windows/http_upload.h"

using google_breakpad::ClientInfo;
using google_breakpad::CrashGenerationServer;

bool clientConnected = false;
bool exitServer = false;

std::wstring wdump = L"";
std::vector<google_breakpad::CustomInfoEntry> customInfo;

static void _cdecl OnClientConnected(void *context, const ClientInfo *client_info)
{
  clientConnected = true;
}

static void _cdecl OnClientCrashed(void *context, const ClientInfo *client_info,
                                   const std::wstring *dump_path)
{
  if(dump_path)
  {
    wdump = *dump_path;

    google_breakpad::CustomClientInfo custom = client_info->GetCustomInfo();

    for(size_t i = 0; i < custom.count; i++)
      customInfo.push_back(custom.entries[i]);
  }

  exitServer = true;
}

static void _cdecl OnClientExited(void *context, const ClientInfo *client_info)
{
  exitServer = true;
}
#endif

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
  if(msg == WM_CLOSE)
  {
    DestroyWindow(hwnd);
    return 0;
  }
  if(msg == WM_DESTROY)
  {
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProc(hwnd, msg, wParam, lParam);
}

void Daemonise()
{
  // nothing really to do, windows version of renderdoccmd is already 'detached'
}

WindowingData DisplayRemoteServerPreview(bool active, const rdcarray<WindowingSystem> &systems)
{
  static WindowingData remoteServerPreview = {WindowingSystem::Unknown};

  if(active)
  {
    if(remoteServerPreview.system == WindowingSystem::Unknown)
    {
      // if we're first initialising, create the window

      RECT wr = {0, 0, (LONG)1280, (LONG)720};
      AdjustWindowRect(&wr, WS_OVERLAPPEDWINDOW, FALSE);

      HWND wnd =
          CreateWindowEx(WS_EX_CLIENTEDGE, L"renderdoccmd", L"Remote Server Preview",
                         WS_OVERLAPPED | WS_CAPTION | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
                         wr.right - wr.left, wr.bottom - wr.top, NULL, NULL, hInstance, NULL);

      if(wnd == NULL)
        return remoteServerPreview;

      ShowWindow(wnd, SW_SHOW);
      UpdateWindow(wnd);

      remoteServerPreview.system = WindowingSystem::Win32;
      remoteServerPreview.win32.window = wnd;
    }
    else
    {
      // otherwise, pump messages
      MSG msg;
      ZeroMemory(&msg, sizeof(msg));

      // Check to see if any messages are waiting in the queue
      while(PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
      {
        // Translate the message and dispatch it to WindowProc()
        TranslateMessage(&msg);
        DispatchMessage(&msg);
      }
    }
  }
  else
  {
    // if we had a previous window, destroy it.
    if(remoteServerPreview.win32.window != NULL)
      DestroyWindow(remoteServerPreview.win32.window);

    // reset the windowing data to 'no window'
    remoteServerPreview = {WindowingSystem::Unknown};
  }

  return remoteServerPreview;
}

void DisplayRendererPreview(IReplayController *renderer, TextureDisplay &displayCfg, uint32_t width,
                            uint32_t height, uint32_t numLoops)
{
  RECT wr = {0, 0, (LONG)width, (LONG)height};
  AdjustWindowRect(&wr, WS_OVERLAPPEDWINDOW, FALSE);

  HWND wnd = CreateWindowEx(WS_EX_CLIENTEDGE, L"renderdoccmd", L"renderdoccmd", WS_OVERLAPPEDWINDOW,
                            CW_USEDEFAULT, CW_USEDEFAULT, wr.right - wr.left, wr.bottom - wr.top,
                            NULL, NULL, hInstance, NULL);

  if(wnd == NULL)
    return;

  ShowWindow(wnd, SW_SHOW);
  UpdateWindow(wnd);

  IReplayOutput *out =
      renderer->CreateOutput(CreateWin32WindowingData(wnd), ReplayOutputType::Texture);

  out->SetTextureDisplay(displayCfg);

  uint32_t loopCount = 0;

  MSG msg;
  ZeroMemory(&msg, sizeof(msg));
  while(true)
  {
    // Check to see if any messages are waiting in the queue
    while(PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
    {
      // Translate the message and dispatch it to WindowProc()
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }

    // If the message is WM_QUIT, exit the while loop
    if(msg.message == WM_QUIT)
      break;

    // set to random event beyond the end of the frame to ensure output is marked as dirty
    renderer->SetFrameEvent(10000000, true);
    out->Display();

    Sleep(40);

    loopCount++;

    if(numLoops > 0 && loopCount == numLoops)
      break;
  }

  DestroyWindow(wnd);
}

struct UpgradeCommand : public Command
{
private:
  std::wstring wide_path;

public:
  UpgradeCommand() {}
  virtual void AddOptions(cmdline::parser &parser) { parser.add<std::string>("path", 0, ""); }
  virtual const char *Description() { return "Internal use only!"; }
  virtual bool IsInternalOnly() { return true; }
  virtual bool IsCaptureCommand() { return false; }
  virtual bool Parse(cmdline::parser &parser, GlobalEnvironment &)
  {
    wide_path = conv(parser.get<std::string>("path"));
    return true;
  }

  virtual int Execute(const CaptureOptions &)
  {
    if(wide_path.back() != '\\' && wide_path.back() != '/')
      wide_path += L'\\';

    // Wait for UI to exit
    Sleep(3000);

    mz_zip_archive zip;
    ZeroMemory(&zip, sizeof(zip));

    bool successful = false;
    std::wstring failReason = L"\"Unknown error\"";

    mz_bool b = mz_zip_reader_init_file(&zip, "./update.zip", 0);

    if(b)
    {
      mz_uint numfiles = mz_zip_reader_get_num_files(&zip);

      // first create directories
      for(mz_uint i = 0; i < numfiles; i++)
      {
        if(mz_zip_reader_is_file_a_directory(&zip, i))
        {
          mz_zip_archive_file_stat zstat;
          mz_zip_reader_file_stat(&zip, i, &zstat);

          const char *fn = zstat.m_filename;
          // skip first directory because it's RenderDoc_Version_Bitness/
          fn = strchr(fn, '/');
          if(fn)
            fn++;

          if(fn && *fn)
          {
            wchar_t conv[MAX_PATH] = {0};
            wchar_t *wfn = conv;

            // I know the zip only contains ASCII chars, just upcast
            while(*fn)
              *(wfn++) = wchar_t(*(fn++));

            std::wstring target = wide_path + conv;

            wfn = &target[0];

            // convert slashes because CreateDirectory barfs on
            // proper slashes.
            while(*(wfn++))
            {
              if(*wfn == L'/')
                *wfn = L'\\';
            }

            CreateDirectoryW(target.c_str(), NULL);
          }
        }
      }

      // next make sure we can get read+write access to every file. If not
      // one might be in use, but we definitely can't update it
      successful = true;

      for(mz_uint i = 0; successful && i < numfiles; i++)
      {
        if(!mz_zip_reader_is_file_a_directory(&zip, i))
        {
          mz_zip_archive_file_stat zstat;
          mz_zip_reader_file_stat(&zip, i, &zstat);

          const char *fn = zstat.m_filename;
          // skip first directory because it's RenderDoc_Version_Bitness/
          fn = strchr(fn, '/');
          if(fn)
            fn++;

          if(fn && *fn)
          {
            wchar_t conv[MAX_PATH] = {0};
            wchar_t *wfn = conv;

            // I know the zip only contains ASCII chars, just upcast
            while(*fn)
              *(wfn++) = wchar_t(*(fn++));

            std::wstring target = wide_path + conv;

            wfn = &target[0];

            // convert slashes just to be consistent
            while(*(wfn++))
            {
              if(*wfn == L'/')
                *wfn = L'\\';
            }

            FILE *f = NULL;
            _wfopen_s(&f, target.c_str(), L"a+");
            if(!f)
            {
              failReason = L"\"Couldn't modify an install file - likely file is in use.\"";
              successful = false;
            }
            else
            {
              fclose(f);
            }
          }
        }
      }

      for(mz_uint i = 0; successful && i < numfiles; i++)
      {
        if(!mz_zip_reader_is_file_a_directory(&zip, i))
        {
          mz_zip_archive_file_stat zstat;
          mz_zip_reader_file_stat(&zip, i, &zstat);

          const char *fn = zstat.m_filename;
          // skip first directory because it's RenderDoc_Version_Bitness/
          fn = strchr(fn, '/');
          if(fn)
            fn++;

          if(fn && *fn)
          {
            wchar_t conv[MAX_PATH] = {0};
            wchar_t *wfn = conv;

            // I know the zip only contains ASCII chars, just upcast
            while(*fn)
              *(wfn++) = wchar_t(*(fn++));

            std::wstring target = wide_path + conv;

            wfn = &target[0];

            // convert slashes just to be consistent
            while(*(wfn++))
            {
              if(*wfn == L'/')
                *wfn = L'\\';
            }

            FILE *target_file = NULL;
            _wfopen_s(&target_file, target.c_str(), L"wb");
            if(target_file)
            {
              mz_zip_reader_extract_to_cfile(&zip, i, target_file, 0);
              fclose(target_file);
            }
          }
        }
      }
    }
    else
    {
      failReason = L"\"Failed to open update .zip file - possibly corrupted.\"";
    }

    // run original UI exe and tell it an update succeeded
    std::wstring cmdline = L"\"";
    cmdline += wide_path;
    cmdline += L"/qrenderdoc.exe\" ";
    if(successful)
      cmdline += L"--updatedone";
    else
      cmdline += L"--updatefailed " + failReason;

    wchar_t *paramsAlloc = new wchar_t[512];

    ZeroMemory(paramsAlloc, sizeof(wchar_t) * 512);

    wcscpy_s(paramsAlloc, 511, cmdline.c_str());

    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));

    CreateProcessW(NULL, paramsAlloc, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    if(pi.dwProcessId != 0)
    {
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    }

    delete[] paramsAlloc;

    return 0;
  }
};

#if CRASH_HANDLER
struct CrashHandlerCommand : public Command
{
private:
  std::wstring pipe;

public:
  CrashHandlerCommand() {}
  virtual void AddOptions(cmdline::parser &parser) { parser.add<std::string>("pipe", 0, ""); }
  virtual const char *Description() { return "Internal use only!"; }
  virtual bool IsInternalOnly() { return true; }
  virtual bool IsCaptureCommand() { return false; }
  virtual bool Parse(cmdline::parser &parser, GlobalEnvironment &)
  {
    pipe = conv(parser.get<std::string>("pipe"));
    return true;
  }
  virtual int Execute(const CaptureOptions &)
  {
    CrashGenerationServer *crashServer = NULL;

    wchar_t tempPath[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH - 1, tempPath);

    std::wstring dumpFolder = tempPath;

    // create each parent directory separately, and use \\s

    dumpFolder += L"RenderDoc";
    CreateDirectoryW(dumpFolder.c_str(), NULL);

    dumpFolder += L"\\dumps";
    CreateDirectoryW(dumpFolder.c_str(), NULL);

    crashServer =
        new CrashGenerationServer(pipe.c_str(), NULL, OnClientConnected, NULL, OnClientCrashed,
                                  NULL, OnClientExited, NULL, NULL, NULL, true, &dumpFolder);

    if(!crashServer->Start())
    {
      delete crashServer;
      crashServer = NULL;
      return 1;
    }

    HANDLE readyEvent = CreateEventA(NULL, TRUE, FALSE, "RENDERDOC_CRASHHANDLE");

    if(readyEvent != NULL)
    {
      SetEvent(readyEvent);

      CloseHandle(readyEvent);
    }

    const int loopSleep = 100;
    int elapsedTime = 0;

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));
    while(!exitServer)
    {
      // Check to see if any messages are waiting in the queue
      while(PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
      {
        // Translate the message and dispatch it to WindowProc()
        TranslateMessage(&msg);
        DispatchMessage(&msg);
      }

      // If the message is WM_QUIT, exit the while loop
      if(msg.message == WM_QUIT)
        break;

      Sleep(loopSleep);
      elapsedTime += loopSleep;

      // break out of the loop if
      if(elapsedTime > 5000 && !clientConnected)
        break;
    }

    delete crashServer;
    crashServer = NULL;

    std::wstring wlogpath;

    if(!wdump.empty())
    {
      std::string report = "{\n";

      for(size_t i = 0; i < customInfo.size(); i++)
      {
        std::wstring name = customInfo[i].name;
        std::wstring val = customInfo[i].value;

        if(name == L"logpath")
        {
          wlogpath = val;
        }
        else if(name == L"ptime")
        {
          // breakpad uptime, ignore.
        }
        else
        {
          report += "  \"" + conv(name) + "\": \"" + conv(val) + "\",\n";
        }
      }

      FILETIME filetime = {};
      SYSTEMTIME systime = {};
      GetSystemTimeAsFileTime(&filetime);
      FileTimeToSystemTime(&filetime, &systime);

      uint32_t milliseconds = 0;
      milliseconds += systime.wHour;
      milliseconds *= 60;
      milliseconds += systime.wMinute;
      milliseconds *= 60;
      milliseconds += systime.wSecond;
      milliseconds *= 1000;
      milliseconds += systime.wMilliseconds;

      std::string dumpId;

      char base62[63] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
      while(milliseconds > 0)
      {
        char c = base62[milliseconds % 63];
        dumpId.push_back(base62[milliseconds % 62]);
        milliseconds /= 62;
      }

      std::string reportPath = conv(dumpFolder) + "\\" + dumpId + ".zip";

      {
        rdcstr tmp = rdcstr(reportPath.c_str(), reportPath.size());
        RENDERDOC_CreateBugReport(conv(wlogpath).c_str(), conv(wdump).c_str(), tmp);
      }

      for(size_t i = 0; i < reportPath.size(); i++)
        if(reportPath[i] == '\\')
          reportPath[i] = '/';

      report += "  \n\"report\": \"" + reportPath + "\"\n";
      report += "}\n";

      {
        std::wstring destjson = dumpFolder + L"\\" + conv(dumpId) + L".json";

        FILE *f = NULL;
        _wfopen_s(&f, destjson.c_str(), L"w");
        if(!f)
        {
          OutputDebugStringA("Coudln't open report json");
        }
        else
        {
          fputs(report.c_str(), f);
          fclose(f);

          wchar_t *paramsAlloc = new wchar_t[512];

          ZeroMemory(paramsAlloc, sizeof(wchar_t) * 512);

          GetModuleFileNameW(NULL, paramsAlloc, 511);

          wchar_t *lastSlash = wcsrchr(paramsAlloc, '\\');

          if(lastSlash)
            *lastSlash = 0;

          std::wstring exepath = paramsAlloc;

          ZeroMemory(paramsAlloc, sizeof(wchar_t) * 512);

          _snwprintf_s(paramsAlloc, 511, 511, L"%s/qrenderdoc.exe --crash %s", exepath.c_str(),
                       destjson.c_str());

          PROCESS_INFORMATION pi;
          STARTUPINFOW si;
          ZeroMemory(&pi, sizeof(pi));
          ZeroMemory(&si, sizeof(si));

          BOOL success = CreateProcessW(NULL, paramsAlloc, NULL, NULL, FALSE, 0, NULL,
                                        exepath.c_str(), &si, &pi);

          if(success && pi.hProcess)
          {
            WaitForSingleObject(pi.hProcess, INFINITE);
          }

          if(pi.hProcess)
            CloseHandle(pi.hProcess);
          if(pi.hThread)
            CloseHandle(pi.hThread);

          std::wstring wreport = conv(reportPath);

          DeleteFileW(wreport.c_str());
          DeleteFileW(destjson.c_str());
        }
      }
    }

    if(!wdump.empty())
      DeleteFileW(wdump.c_str());

    if(!wlogpath.empty())
      DeleteFileW(wlogpath.c_str());

    return 0;
  }
};
#endif

struct GlobalHookCommand : public Command
{
private:
  std::wstring wpathmatch;
  std::string capfile;
  std::string debuglog;
  std::string opts;

public:
  GlobalHookCommand() {}
  virtual void AddOptions(cmdline::parser &parser)
  {
    parser.add<std::string>("match", 0, "");
    parser.add<std::string>("capfile", 0, "");
    parser.add<std::string>("debuglog", 0, "");
    parser.add<std::string>("capopts", 0, "");
  }
  virtual const char *Description() { return "Internal use only!"; }
  virtual bool IsInternalOnly() { return true; }
  virtual bool IsCaptureCommand() { return false; }
  virtual bool Parse(cmdline::parser &parser, GlobalEnvironment &)
  {
    wpathmatch = conv(parser.get<std::string>("match"));
    capfile = parser.get<std::string>("capfile");
    debuglog = parser.get<std::string>("debuglog");
    opts = parser.get<std::string>("capopts");
    return true;
  }
  virtual int Execute(const CaptureOptions &)
  {
    CaptureOptions cmdopts;
    cmdopts.DecodeFromString(rdcstr(opts.c_str(), opts.size()));

    // make sure the user doesn't accidentally run this with 'a' as a parameter or something.
    // "a.exe" is over 4 characters so this limit should not be a problem.
    if(wpathmatch.length() < 4)
    {
      std::cerr
          << "globalhook path match is too short/general. Danger of matching too many processes!"
          << std::endl;
      return 1;
    }

    wchar_t rdocpath[1024];

    // fetch path to our matching renderdoc.dll
    HMODULE rdoc = GetModuleHandleA("renderdoc.dll");

    if(rdoc == NULL)
    {
      std::cerr << "globalhook couldn't find renderdoc.dll!" << std::endl;
      return 1;
    }

    GetModuleFileNameW(rdoc, rdocpath, _countof(rdocpath) - 1);
    FreeLibrary(rdoc);

    // Create stdin pipe from parent program, to stay open until requested to close
    HANDLE pipe = GetStdHandle(STD_INPUT_HANDLE);

    if(pipe == INVALID_HANDLE_VALUE)
    {
      std::cerr << "globalhook couldn't open stdin pipe.\n" << std::endl;
      return 1;
    }

    HANDLE datahandle = OpenFileMappingA(FILE_MAP_READ, FALSE, GLOBAL_HOOK_DATA_NAME);

    if(datahandle != NULL)
    {
      CloseHandle(pipe);
      CloseHandle(datahandle);
      std::cerr << "globalhook found pre-existing global data, not creating second global hook."
                << std::endl;
      return 1;
    }

    datahandle = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(ShimData),
                                    GLOBAL_HOOK_DATA_NAME);

    if(datahandle)
    {
      ShimData *shimdata = (ShimData *)MapViewOfFile(datahandle, FILE_MAP_WRITE | FILE_MAP_READ, 0,
                                                     0, sizeof(ShimData));

      if(shimdata)
      {
        memset(shimdata, 0, sizeof(ShimData));

        wcsncpy_s(shimdata->pathmatchstring, wpathmatch.c_str(), _TRUNCATE);
        wcsncpy_s(shimdata->rdocpath, rdocpath, _TRUNCATE);
        strncpy_s(shimdata->capfile, capfile.c_str(), _TRUNCATE);
        strncpy_s(shimdata->debuglog, debuglog.c_str(), _TRUNCATE);
        memcpy(shimdata->opts, &cmdopts, sizeof(CaptureOptions));

        static_assert(sizeof(CaptureOptions) <= sizeof(shimdata->opts),
                      "ShimData options is too small");

        // wait until a write comes in over the pipe
        char buf[16] = {0};
        DWORD read = 0;
        ReadFile(pipe, buf, sizeof(buf), &read, NULL);

        UnmapViewOfFile(shimdata);
      }
      else
      {
        std::cerr << "globalhook couldn't map global data store." << std::endl;
      }

      CloseHandle(datahandle);
    }
    else
    {
      std::cerr << "globalhook couldn't create global data store." << std::endl;
    }

    CloseHandle(pipe);

    return 0;
  }
};

std::atomic<bool> kill(false);
std::atomic_flag ping_flag = ATOMIC_FLAG_INIT;

void ping_server(IRemoteServer* remote)
{
  bool success = true;
  while(success && !kill) 
  {
    success = remote->Ping();
    Sleep(1000);
  }
}

// ignore the argc/argv we get here, convert from wide to be sure we're unicode safe.
int main(int, char *)
{
  LPWSTR *wargv;
  int argc;

  wargv = CommandLineToArgvW(GetCommandLine(), &argc);

  std::vector<std::string> argv;

  argv.resize(argc);
  for(size_t i = 0; i < argv.size(); i++)
    argv[i] = conv(std::wstring(wargv[i]));

  if(argv.size() != 2)
  {
    std::cerr << "packageName/mainActivity is needed" << std::endl;
  }
  LocalFree(wargv);

  std::string packageName = argv[1];

  RENDERDOC_InitialiseReplay(GlobalEnvironment(), NULL);
  rdcarray<rdcstr> protocols;
  RENDERDOC_GetSupportedDeviceProtocols(&protocols);
  for(const rdcstr &p : protocols)
  {
    IDeviceProtocolController *controller = RENDERDOC_GetDeviceProtocolController(p);
    IRemoteServer *remote = NULL;
    rdcstr urlrdc = rdcstr("adb://") + controller->GetDevices()[0];
    const char* url = urlrdc.c_str();
    ReplayStatus status = RENDERDOC_CreateRemoteServerConnection(url, &remote);

    if(status == ReplayStatus::NetworkIOFailed)
    {
      ReplayStatus status = controller->StartRemoteServer(urlrdc);
      std::cout << ToStr(status).c_str() << std::endl;
      status = RENDERDOC_CreateRemoteServerConnection(url, &remote);
      if(remote == NULL || status != ReplayStatus::Succeeded)
      {
        std::cerr << "Error: " << ToStr(status).c_str() << " - Couldn't connect to "
                  << controller->GetDevices()[0].c_str() << "." << std::endl;
        std::cerr << "       Have you run renderdoccmd remoteserver on '"
                  << controller->GetDevices()[0].c_str() << "'?" << std::endl;
        return 1;
      }
	}	   

    CaptureOptions opts;
    RENDERDOC_GetDefaultCaptureOptions(&opts);
    ExecuteResult result = remote->ExecuteAndInject(packageName.c_str(), NULL, NULL, NULL, opts);
    if(result.status != ReplayStatus::Succeeded)
    {
      std::cout << ToStr(result.status).c_str() << std::endl;
      remote->ShutdownServerAndConnection();
      return 1;
    }

	std::cout << "game started" << std::endl;
	std::thread ping_thread(ping_server, remote);

	ITargetControl *conn = RENDERDOC_CreateTargetControl(url, result.ident, "test", true);
    if(!conn)
    {
      kill = true;
      ping_thread.join();
      remote->ShutdownServerAndConnection();
      std::cerr << "       Couldn't connect to target control for " << packageName << "." << std::endl;
      return 1;
    }

    std::string line;
    while(getline(std::cin, line))
    {
      if(line.compare(0, 4, "exit") == 0)
      {
        conn->Shutdown();
        kill = true;
        ping_thread.join();
        remote->ShutdownServerAndConnection();
        RENDERDOC_ShutdownReplay();
        return 0;
	  }
      else
      {
		conn->TriggerCapture(1);

        std::cout << "capture done" << std::endl;

        TargetControlMessage *msg = NULL;
        clock_t start = clock();
        while(msg == NULL || msg->type != TargetControlMessageType::NewCapture)
        {
          msg = &conn->ReceiveMessage(NULL);
          if((clock() - start) / CLOCKS_PER_SEC > 30)
          {
            std::cout << "capture time out" << std::endl;
            break;
          }
        }

        if(msg->type != TargetControlMessageType::NewCapture)
        {
          remote->ShutdownServerAndConnection();
          std::cerr << "Didn't get new capture notification after triggering capture" << std::endl;
          return 1;
        }
        rdcstr cap_path = msg->newCapture.path;
        std::cout << "Got new capture at " << cap_path.c_str() << " which is frame "
                  << msg->newCapture.frameNumber << std::endl;
        remote->CopyCaptureFromRemote(cap_path.c_str(), ("D:\\"+line+".rdc").c_str(), NULL);
        //Sleep(1);
        //conn->DeleteCapture(msg->newCapture.captureId);

        std::cout << "copy capture done" << std::endl;
	  }
    }
  }



 /* TCPServer tcpServer{27015};
  tcpServer.Run();

  std::puts("Press enter to close server");
  std::getc(stdin);*/

  return 0;
}
