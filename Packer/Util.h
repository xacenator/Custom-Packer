#pragma once
#pragma once
#include <string>
namespace Util {
	std::wstring GetDesktopPath();
	std::string  WStringToString(const std::wstring&);
	std::wstring ToWString(const std::string&);
	std::wstring GetFileNameWithoutExt(const std::wstring&);
}
