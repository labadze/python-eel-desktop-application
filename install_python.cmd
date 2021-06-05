SET mypath=%~dp0
python-3.9.5-amd64.exe /quiet InstallAllUsers=0 TARGET=%mypath:~0,-1% DefaultJustForMeTargetDir=%mypath:~0,-1% DefaultCustomTargetDir=%mypath:~0,-1% Shortcuts=0 Include_doc=0 SimpleInstall=1 PrependPath=1 Include_test=1
pause