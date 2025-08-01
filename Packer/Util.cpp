// src/Util.cpp
#include "Util.h"
#include <windows.h>
#include <shlobj.h>
#include <stdexcept>

namespace Util {

std::wstring GetDesktopPath() {
  PWSTR path = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &path)))
    throw std::runtime_error("Cannot find Desktop folder");
  std::wstring w(path);
  CoTaskMemFree(path);
  return w;
}

std::string WStringToString(const std::wstring& w) {
  int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string s(sz, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
  return s;
}

std::wstring ToWString(const std::string& s) {
  int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
  std::wstring w(sz, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], sz);
  return w;
}

std::wstring GetFileNameWithoutExt(const std::wstring& path) {
  size_t pos = path.find_last_of(L"\\/");  
  std::wstring name = (pos == std::wstring::npos ? path : path.substr(pos + 1));
  size_t dot = name.find_last_of(L'.');
  return (dot == std::wstring::npos ? name : name.substr(0, dot));
}

} // namespace Util
