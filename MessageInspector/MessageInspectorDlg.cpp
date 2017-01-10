
// MessageInspectorDlg.cpp : implementation file
//

#include "stdafx.h"
#include "MessageInspector.h"
#include "MessageInspectorDlg.h"
#include "afxdialogex.h"

#include "openpgp\openpgp_message.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMessageInspectorDlg dialog



CMessageInspectorDlg::CMessageInspectorDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MESSAGEINSPECTOR_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMessageInspectorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMessageInspectorDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON2, &CMessageInspectorDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CMessageInspectorDlg message handlers

BOOL CMessageInspectorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CMessageInspectorDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CMessageInspectorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CMessageInspectorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMessageInspectorDlg::OnBnClickedButton2()
{
	char *inputBuffer = NULL;
	SIZE_T szClipboardData = 0;
	BOOL clipboardOpened = OpenClipboard();

	if (clipboardOpened) {
		HANDLE hClipboardData = GetClipboardData(CF_UNICODETEXT);
		if (hClipboardData) {
			// copy the unicode text from the clipboard
			LPCTSTR lpClipboardData = (LPCTSTR)GlobalLock(hClipboardData);
			if (lpClipboardData) {
				szClipboardData = GlobalSize(hClipboardData);

				size_t elements = szClipboardData / sizeof(wchar_t);
				size_t count = wcsnlen(lpClipboardData, elements);

				int ret = WideCharToMultiByte(CP_UTF8, 0, lpClipboardData, -1, NULL, 0, NULL, NULL);
				if (ret > 0) {
					inputBuffer =(char *)malloc(ret);
					if (inputBuffer) {
						if (WideCharToMultiByte(CP_UTF8, 0, lpClipboardData, -1, inputBuffer, ret, NULL, NULL) > 0) {
							import_utf8_data(inputBuffer, ret);
						}
					}
					else {
						AfxMessageBox(_T("Could not allocate output buffer for UTF8 conversion"));
					}
				}
				else {
					AfxMessageBox(_T("Could not convert clipboard text to UTF8"));
				}
			}
		}
		else {
			AfxMessageBox(_T("Could not retrieve data with format CF_UNICODETEXT from clipboard."));
		}
		CloseClipboard();
	}
	else {
		AfxMessageBox(_T("Could not open clipboard."));
	}
}

BOOL CMessageInspectorDlg::import_utf8_data(char * buffer, size_t buffer_len)
{
	if (buffer) {
		OPENPGP_MESSAGE *firstMessage = search_for_openpgp_msg(buffer, buffer_len, 0);
		if (firstMessage) {
			int validity = validate_message(firstMessage, 0);
			OPENPGP_PACKET *message_packet_chain = packetize_openpgp_message(firstMessage);
			AfxMessageBox(_T("Found message"));
		}
		else {
			AfxMessageBox(_T("No ASCII armoured PGP message found in clipboard."));
		}
	}

	return 0;
}
