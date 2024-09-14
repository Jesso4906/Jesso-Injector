#include "MainGui.h"

wxBEGIN_EVENT_TABLE(MainGui, wxFrame)
EVT_CLOSE(CloseApp)
EVT_BUTTON(SelectProcessID, OpenSelectProcessMenu)
EVT_BUTTON(FileSelectorID, SelectDllFile)
EVT_CHOICE(InjectionMethodChoiceID, UpdateInjectionMethod)
EVT_BUTTON(InjectButtonID, InjectDll)
wxEND_EVENT_TABLE()

#if _WIN64
MainGui::MainGui() : wxFrame(nullptr, MainWindowID, "Jesso Injector x64", wxPoint(50, 50), wxSize(650, 280))
#else
MainGui::MainGui() : wxFrame(nullptr, MainWindowID, "Jesso Injector x86", wxPoint(50, 50), wxSize(650, 280))
#endif
{
	SetOwnBackgroundColour(backgroundColor);

	selectProcessMenu = new SelectProcessMenu(this);

	processSelectButton = new wxButton(this, SelectProcessID, "Select process to inject DLL into", wxPoint(0, 0), wxSize(250, 25));
	processSelectButton->SetOwnBackgroundColour(foregroundColor);
	processSelectButton->SetOwnForegroundColour(textColor);

	selectedProcessStaticText = new wxStaticText(this, wxID_ANY, "Selected Process:");
	selectedProcessStaticText->SetOwnForegroundColour(textColor);

	dllPathTextCtrl = new wxTextCtrl(this, wxID_ANY, "DLL Path", wxPoint(0, 0), wxSize(525, 25));
	dllPathTextCtrl->SetOwnBackgroundColour(foregroundColor);
	dllPathTextCtrl->SetOwnForegroundColour(textColor);

	dllSelectorButton = new wxButton(this, FileSelectorID, "Open File", wxPoint(0, 0), wxSize(80, 25));
	dllSelectorButton->SetOwnBackgroundColour(foregroundColor);
	dllSelectorButton->SetOwnForegroundColour(textColor);

	rememberPathCheckBox = new wxCheckBox(this, wxID_ANY, "Remember DLL path");
	rememberPathCheckBox->SetOwnForegroundColour(textColor);

	injectionMethodChoice = new wxChoice(this, InjectionMethodChoiceID, wxPoint(0, 0), wxSize(350, 50), wxArrayString(numberOfInjectionMethods, injectionMethodStrs));
	injectionMethodChoice->SetSelection(LoadLibraryARemoteThread);
	injectionMethodChoice->SetOwnBackgroundColour(foregroundColor);
	injectionMethodChoice->SetOwnForegroundColour(textColor);

	showStatusMessageBoxCheckBox = new wxCheckBox(this, wxID_ANY, "Show status message box");
	showStatusMessageBoxCheckBox->SetOwnForegroundColour(textColor);
	showStatusMessageBoxCheckBox->SetValue(true);

	threadIdTextCtrl = new wxTextCtrl(this, wxID_ANY, "Thread Id (-1 for first thread)", wxPoint(0, 0), wxSize(160, 25));
	threadIdTextCtrl->SetOwnBackgroundColour(foregroundColor);
	threadIdTextCtrl->SetOwnForegroundColour(textColor);
	threadIdTextCtrl->Hide();

	injectButton = new wxButton(this, InjectButtonID, "Inject", wxPoint(0, 0), wxSize(100, 25));
	injectButton->SetOwnBackgroundColour(foregroundColor);
	injectButton->SetOwnForegroundColour(textColor);

	row1Sizer = new wxBoxSizer(wxHORIZONTAL);
	row2Sizer = new wxBoxSizer(wxHORIZONTAL);
	vSizer = new wxBoxSizer(wxVERTICAL);

	row1Sizer->Add(processSelectButton, 0, wxALL, 10);
	row1Sizer->Add(selectedProcessStaticText, 0, wxTOP | wxBOTTOM, 10);

	row2Sizer->Add(dllPathTextCtrl, 0, wxLEFT, 10);
	row2Sizer->Add(dllSelectorButton, 0, wxLEFT, 10);

	vSizer->Add(row1Sizer, 0, wxEXPAND);
	vSizer->Add(row2Sizer, 0, wxEXPAND);
	vSizer->Add(rememberPathCheckBox, 0, wxLEFT | wxTOP, 10);
	vSizer->Add(injectionMethodChoice, 0, wxLEFT | wxTOP, 10);
	vSizer->Add(threadIdTextCtrl, 0, wxLEFT, 10);
	vSizer->Add(showStatusMessageBoxCheckBox, 0, wxLEFT | wxTOP, 10);
	vSizer->Add(injectButton, 0, wxLEFT | wxTOP, 10);

	SetSizer(vSizer);

	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, MAX_PATH);

	std::string savedFilePath(path);
	savedFilePath = savedFilePath.substr(0, savedFilePath.find_last_of("\\") + 1);
	savedFilePath += "JessoInjectorSavedPath.txt";

	std::ifstream savedFileStream(savedFilePath);

	if (savedFileStream)
	{
		savedFileStream.read(path, MAX_PATH);

		dllPathTextCtrl->SetValue(path);
		rememberPathCheckBox->SetValue(true);

		savedFileStream.close();
	}
}

void MainGui::OpenSelectProcessMenu(wxCommandEvent& e)
{
	selectProcessMenu->OpenMenu(GetPosition());
}

void MainGui::SelectDllFile(wxCommandEvent& e)
{
	wxFileDialog openDllDialog(this, "Choose dll file to inject into the target process", "", "", "DLL files (*.dll)|*.dll", wxFD_FILE_MUST_EXIST);

	if (openDllDialog.ShowModal() != wxID_CANCEL)
	{
		dllPathTextCtrl->SetValue(openDllDialog.GetPath());
	}

	openDllDialog.Close();
}

void MainGui::UpdateInjectionMethod(wxCommandEvent& e)
{
	injectionMethod = (InjectionMethod)injectionMethodChoice->GetSelection();

	if (injectionMethod == LoadLibraryAHijackThread || injectionMethod == ManuallyMapHijackThread) 
	{
		threadIdTextCtrl->Show();
		Layout();
	}
	else 
	{
		threadIdTextCtrl->Hide();
		Layout();
	}
}

void MainGui::InjectDll(wxCommandEvent& e)
{
	if (!targetProcessHandle) 
	{
		wxMessageBox("Target proccess not selected", "Can't Inject");
		return;
	}

	int threadId = -1;
	if (injectionMethod == LoadLibraryAHijackThread || injectionMethod == ManuallyMapHijackThread) 
	{
		if (!threadIdTextCtrl->GetValue().ToInt(&threadId)) 
		{
			wxMessageBox("Invalid thread ID", "Can't Inject");
			return;
		}
	}

	InjectionResult result = Success;
	switch(injectionMethod)
	{
	case LoadLibraryARemoteThread:
		result = InjectByLoadLibraryA(targetProcessHandle, dllPathTextCtrl->GetValue().c_str());
		break;
	case LoadLibraryAHijackThread:
		result = InjectByThreadHijack(targetProcessHandle, dllPathTextCtrl->GetValue().c_str(), threadId);
		break;
	case ManuallyMapRemoteThread:
		result = InjectByManuallyMapping(targetProcessHandle, dllPathTextCtrl->GetValue().c_str(), false, -1);
		break;
	case ManuallyMapHijackThread:
		result = InjectByManuallyMapping(targetProcessHandle, dllPathTextCtrl->GetValue().c_str(), true, threadId);
		break;
	}

	if (!showStatusMessageBoxCheckBox->IsChecked()) { return; }

	wxString resultStr = "";
	switch (result) 
	{
	case Success:
		resultStr = "Successfully injected DLL into target process.";
		break;
	case FileNotFound:
		resultStr = "DLL file not found.";
		break;
	case FailedVirtualAllocEx:
		resultStr = "VirtualAllocEx failed.";
		break;
	case FailedWriteProcessMemory:
		resultStr = "WriteProcessMemory failed.";
		break;
	case FailedCreateRemoteThread:
		resultStr = "CreateRemoteThread failed.";
		break;
	case FailedOpenThread:
		resultStr = "OpenThread failed.";
		break;
	case FailedCreateThreadSnapshot:
		resultStr = "Failed to create snapshot of threads.";
		break;
	case FailedGetThreadContext:
		resultStr = "GetThreadContext failed.";
		break;
	case FailedToOpenFile:
		resultStr = "Failed to open DLL file.";
		break;
	}

	wxMessageBox(resultStr, "Injection Result");
}

void MainGui::CloseApp(wxCloseEvent& e)
{
	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, MAX_PATH);

	std::string savedFilePath(path);
	savedFilePath = savedFilePath.substr(0, savedFilePath.find_last_of("\\") + 1);
	savedFilePath += "JessoInjectorSavedPath.txt";
	
	if (rememberPathCheckBox->IsChecked()) 
	{
		HANDLE saveFile = CreateFileA(savedFilePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (saveFile) 
		{
			WriteFile(saveFile, dllPathTextCtrl->GetValue().c_str().AsChar(), MAX_PATH, NULL, NULL);
			CloseHandle(saveFile);
		}
	}
	else
	{
		DeleteFileA(savedFilePath.c_str());
	}
	
	selectProcessMenu->Destroy();
	Destroy();
}

// select proc menu

wxBEGIN_EVENT_TABLE(SelectProcessMenu, wxFrame)
EVT_CLOSE(CloseMenu)
EVT_TEXT(ProcessNameInputID, SearchProcessList)
EVT_CHECKBOX(UseDebugPrivilegeID, UpdateDebugPrivilege)
EVT_LISTBOX_DCLICK(ProcessListID, SelectProcess)
wxEND_EVENT_TABLE()

SelectProcessMenu::SelectProcessMenu(MainGui* mainPtr) : wxFrame(nullptr, MainWindowID, "Select Process", wxPoint(50, 50), wxSize(400, 400))
{
	main = mainPtr;

	SetOwnBackgroundColour(backgroundColor);

	processNameInput = new wxTextCtrl(this, ProcessNameInputID, "", wxPoint(0, 0), wxSize(9999, 25));
	processNameInput->SetOwnBackgroundColour(foregroundColor);
	processNameInput->SetOwnForegroundColour(textColor);

	useDebugPrivilege = new wxCheckBox(this, UseDebugPrivilegeID, "Use Debug Privilege (must be running as administrator to use)");
	useDebugPrivilege->SetOwnForegroundColour(textColor);

	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
		{
			if (Elevation.TokenIsElevated == FALSE)
			{
				useDebugPrivilege->Disable();
			}
		}
	}
	if (hToken) { CloseHandle(hToken); }

	processList = new wxListBox(this, ProcessListID, wxPoint(0, 0), wxSize(9999, 9999));
	processList->SetOwnBackgroundColour(foregroundColor);
	processList->SetOwnForegroundColour(textColor);

	vSizer = new wxBoxSizer(wxVERTICAL);

	vSizer->Add(processNameInput, 0, wxALL, 10);
	vSizer->Add(useDebugPrivilege, 0, wxRIGHT | wxLEFT | wxBOTTOM, 10);
	vSizer->Add(processList, 0, wxRIGHT | wxLEFT | wxBOTTOM, 10);

	SetSizer(vSizer);
}

void SelectProcessMenu::RefreshProcessList()
{
	processList->Clear();

	originalProcIds.clear();
	originalProcIds.shrink_to_fit();

	std::vector<std::wstring> names;
	int count = 0;
	HANDLE procSnap = (CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (procSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(procSnap, &procEntry))
		{
			do
			{
				if (!_wcsicmp(procEntry.szExeFile, L"svchost.exe")) { continue; }
				
				BOOL is32Bit;
				HANDLE procHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procEntry.th32ProcessID);
				if (!procHandle) { continue; }
				IsWow64Process(procHandle, &is32Bit);
#if _WIN64
				if (is32Bit) { continue; }
#else
				if (!is32Bit) { continue; }
#endif

				names.push_back(std::wstring(procEntry.szExeFile) + L" (" + std::to_wstring(procEntry.th32ProcessID) + L")");
				originalProcIds.push_back(procEntry.th32ProcessID);

				count++;
			} while (Process32Next(procSnap, &procEntry));
		}
	}
	CloseHandle(procSnap);

	std::vector<const wchar_t*> cStrArray;
	cStrArray.reserve(names.size());
	for (int i = 0; i < names.size(); i++)
	{
		cStrArray.push_back(names[i].c_str());
	}

	processNames = new wxArrayString(count, cStrArray.data());
	processList->InsertItems(*processNames, 0);

	currentProcIds = originalProcIds;
}

void SelectProcessMenu::SearchProcessList(wxCommandEvent& e)
{
	wxString input = processNameInput->GetValue().Lower();
	unsigned int inputLen = input.Length();

	if (input.IsEmpty())
	{
		RefreshProcessList();
		return;
	}

	processList->Clear();

	currentProcIds.clear();
	currentProcIds.shrink_to_fit();

	int lastIndex = 0;

	for (int i = 0; i < processNames->GetCount(); i++)
	{
		wxString currentProcessName = processNames->Item(i).Lower();
		unsigned int currentNameLen = currentProcessName.Length();

		for (int j = 0; j < currentNameLen; j++)
		{
			for (int k = 0; k < inputLen; k++)
			{
				if (currentProcessName.GetChar(j + k) != input.GetChar(k))
				{
					break;
				}
				else if (k == inputLen - 1)
				{
					processList->InsertItems(1, &(processNames->Item(i)), lastIndex);
					currentProcIds.push_back(originalProcIds[i]);
					lastIndex++;
				}
			}
		}
	}
}

void SelectProcessMenu::SelectProcess(wxCommandEvent& e)
{
	int selection = processList->GetSelection();

	HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, currentProcIds[selection]);

	if (procHandle)
	{
		main->targetProcessHandle = procHandle;
		main->selectedProcessStaticText->SetLabelText("Selected Process: " + processList->GetString(selection));

		// close this menu
		wxCloseEvent e2;
		CloseMenu(e2);
	}
	else
	{
		wxMessageBox("Failed to open process. You may need to use debug privilege", "Failed to open process");
	}
}

void SelectProcessMenu::UpdateDebugPrivilege(wxCommandEvent& e)
{
	LUID luid;
	LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid);

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	if (useDebugPrivilege->IsChecked())
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // enable
	}
	else
	{
		tp.Privileges[0].Attributes = 0; // disable
	}

	HANDLE accessToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &accessToken);

	AdjustTokenPrivileges(accessToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
}

void SelectProcessMenu::OpenMenu(wxPoint position)
{
	position.x += 10;
	position.y += 10;
	SetPosition(position);
	Show();
	Raise();

	RefreshProcessList();
}

void SelectProcessMenu::CloseMenu(wxCloseEvent& e)
{
	Hide();

	delete processNames;

	originalProcIds.clear();
	originalProcIds.shrink_to_fit();
}