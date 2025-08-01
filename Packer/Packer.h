
#pragma once
#include <string>

class Packer {
public:
	Packer();
	void Pack(const std::wstring& inPath, const std::wstring& outPath);

private:
	struct Impl;
	Impl* p;
};
