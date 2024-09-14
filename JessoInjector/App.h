#pragma once
#include <wx/wx.h>
#include "MainGui.h"

class App : public wxApp
{
public:
	virtual bool OnInit();

private:
	MainGui* mainGui = nullptr;
};