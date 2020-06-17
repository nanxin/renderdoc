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

void Daemonise()
{
}

WindowingData DisplayRemoteServerPreview(bool active, const rdcarray<WindowingSystem> &systems)
{
  return {WindowingSystem::Unknown};
}

void DisplayRendererPreview(IReplayController *renderer, TextureDisplay &displayCfg, uint32_t width,
                            uint32_t height, uint32_t numLoops)
{
}

std::atomic<bool> kill(false);
std::atomic_flag ping_flag = ATOMIC_FLAG_INIT;

void ping_server(IRemoteServer *remote)
{
  bool success = true;
  while(success && !kill)
  {
    success = remote->Ping();
    Sleep(1000);
  }
}

int main(int, char *)
{
  LPWSTR *wargv;
  int argc;

  wargv = CommandLineToArgvW(GetCommandLine(), &argc);

  std::vector<std::string> argv;

  argv.resize(argc);
  for(size_t i = 0; i < argv.size(); i++)
    argv[i] = conv(std::wstring(wargv[i]));

  if(argv.size() != 3)
  {
    std::cerr << "adbDeviceId and packageName/mainActivity is needed" << std::endl;
  }
  LocalFree(wargv);

  std::string adbDeviceId = argv[1];
  std::string packageName = argv[2];

  GlobalEnvironment env = GlobalEnvironment();
  env.enumerateGPUs = false;
  RENDERDOC_InitialiseReplay(env, NULL);

  IRemoteServer *remote = NULL;
  IDeviceProtocolController *controller = NULL;
  ReplayStatus status;
  rdcstr urlrdc;

  rdcarray<rdcstr> protocols;
  RENDERDOC_GetSupportedDeviceProtocols(&protocols);
  for(const rdcstr &p : protocols)
  {
    std::string ps(p.c_str());
    if(ps.compare(0, 4, "adb") == 0)
    {
      controller = RENDERDOC_GetDeviceProtocolController(p);
      for(const rdcstr &d : controller->GetDevices())
      {
        std::string ds(d.c_str());
        if(ds.compare(0, adbDeviceId.size(), adbDeviceId) == 0)
        {
          urlrdc = rdcstr("adb://") + d;
          status = RENDERDOC_CreateRemoteServerConnection(urlrdc.c_str(), &remote);
		}
	  }
	}
 }
 

  if(status == ReplayStatus::NetworkIOFailed)
  {
    ReplayStatus status = controller->StartRemoteServer(urlrdc);
    status = RENDERDOC_CreateRemoteServerConnection(urlrdc.c_str(), &remote);
    if(remote == NULL || status != ReplayStatus::Succeeded)
    {
      std::cerr << "Error: " << ToStr(status).c_str() << " - Couldn't connect to "
                << adbDeviceId << "." << std::endl;
      return 1;
    }
  }

  CaptureOptions opts;
  RENDERDOC_GetDefaultCaptureOptions(&opts);
  ExecuteResult result = remote->ExecuteAndInject(packageName.c_str(), NULL, NULL, NULL, opts);
  if(result.status != ReplayStatus::Succeeded)
  {
    std::cerr << "Error: " << ToStr(result.status).c_str() << " - Couldn't start "
              << packageName << "." << std::endl;
    remote->ShutdownServerAndConnection();
    return 1;
  }

  std::cout << packageName.c_str() << " started." << std::endl;
  std::thread ping_thread(ping_server, remote);

  ITargetControl *conn = RENDERDOC_CreateTargetControl(urlrdc.c_str(), result.ident, "test", true);
  if(!conn)
  {
    kill = true;
    ping_thread.join();
    remote->ShutdownServerAndConnection();
    std::cerr << "Couldn't connect to target control for " << packageName << "." << std::endl;
    return 1;
  }

  std::string line;
  std::vector<uint32_t> toDeleteCaptureIds;
  while(getline(std::cin, line))
  {
    if(line.compare(0, 4, "exit") == 0)
    {
      std::cout << "Exiting..." << std::endl;
      for(size_t i = 0; i < toDeleteCaptureIds.size(); i++)
      {
        conn->DeleteCapture(toDeleteCaptureIds[i]);
	  }
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
      TargetControlMessage *msg = NULL;
      clock_t start = clock();
      while(msg == NULL || msg->type != TargetControlMessageType::NewCapture)
      {
        msg = &conn->ReceiveMessage(NULL);
        if((clock() - start) / CLOCKS_PER_SEC > 30)
        {
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
      remote->CopyCaptureFromRemote(cap_path.c_str(), line.c_str(), NULL);
      toDeleteCaptureIds.push_back(msg->newCapture.captureId);
      std::cout << "Capture saved: " << line << std::endl;
    }
  }

  return 0;
}
