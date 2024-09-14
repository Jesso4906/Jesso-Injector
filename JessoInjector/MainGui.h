#include <wx/wx.h>
#include <fstream> 
#include "JessoInjector.h"

const wxColour backgroundColor = wxColour(35, 35, 35);
const wxColour foregroundColor = wxColour(60, 60, 60);
const wxColour textColor = wxColour(220, 220, 220);

class SelectProcessMenu; // forward delcared becasue it needs to access the Main class

class MainGui : public wxFrame
{
public:
	MainGui();

	SelectProcessMenu* selectProcessMenu = nullptr;
	wxButton* processSelectButton = nullptr;
	wxStaticText* selectedProcessStaticText = nullptr;

	wxTextCtrl* dllPathTextCtrl = nullptr;
	wxButton* dllSelectorButton = nullptr;

	wxCheckBox* rememberPathCheckBox = nullptr;

	wxCheckBox* showStatusMessageBoxCheckBox = nullptr;

	wxChoice* injectionMethodChoice = nullptr;

	wxTextCtrl* threadIdTextCtrl = nullptr;

	wxButton* injectButton = nullptr;

	wxBoxSizer* row1Sizer = nullptr;
	wxBoxSizer* row2Sizer = nullptr;
	wxBoxSizer* vSizer = nullptr;

	HANDLE targetProcessHandle = 0;

	enum ids 
	{
		MainWindowID,
		SelectProcessID,
		FileSelectorID,
		InjectionMethodChoiceID,
		InjectButtonID
	};

	enum InjectionMethod
	{
		LoadLibraryARemoteThread,
		LoadLibraryAHijackThread,
		ManuallyMapRemoteThread,
		ManuallyMapHijackThread
	};

	const static unsigned char numberOfInjectionMethods = 4;

	const char* injectionMethodStrs[numberOfInjectionMethods] =
	{
		"Call LoadLibraryA from a remote thread",
		"Call LoadLibraryA from a hijcaked thread",
		"Manually map dll and run internal code from a remote thread",
		"Manually map dll and run internal code from a hijacked thread"
	};

	InjectionMethod injectionMethod = LoadLibraryARemoteThread;

	void OpenSelectProcessMenu(wxCommandEvent& e);

	void SelectDllFile(wxCommandEvent& e);

	void UpdateInjectionMethod(wxCommandEvent& e);

	void InjectDll(wxCommandEvent& e);

	void CloseApp(wxCloseEvent& e);

	wxDECLARE_EVENT_TABLE();
};


class SelectProcessMenu : public wxFrame
{
public:
	SelectProcessMenu(MainGui* mainPtr);

	MainGui* main = nullptr;

	wxTextCtrl* processNameInput = nullptr;

	wxCheckBox* useDebugPrivilege = nullptr;

	wxListBox* processList = nullptr;

	wxBoxSizer* vSizer = nullptr;

	wxArrayString* processNames = nullptr;

	std::vector<DWORD> originalProcIds;
	std::vector<DWORD> currentProcIds; // after search

	DWORD chosenProc = 0;

	enum ids
	{
		MainWindowID,
		ProcessNameInputID,
		UseDebugPrivilegeID,
		ProcessListID
	};

	void RefreshProcessList();

	void SearchProcessList(wxCommandEvent& e);

	void SelectProcess(wxCommandEvent& e);

	void UpdateDebugPrivilege(wxCommandEvent& e);

	void OpenMenu(wxPoint position);

	void CloseMenu(wxCloseEvent& e);

	wxDECLARE_EVENT_TABLE();
};