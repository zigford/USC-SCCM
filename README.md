Whats New
=========

### 19/02/2019 : New CmdLet Get-CfgDeploymentDetail
* Show deployment status of a deployment, per asset from the command line

### 20/04/2018 : Update to Get-CfgClientInventory (ginv)
* Now supports searching for devices using -PrimaryUser parameter which get's devices based on user device affinity.
* Supports "PrimaryUser" roperty to return when using the -Properties parameter.

TODO
====

Known Issues
============

* If powershell attempts to auto load the module by using tab completion and you haven't launched the module before it silently prompts for a site server name. Press Ctrl+C to cancel and import the module manually
=======
On linux, requires wmic: https://gist.github.com/rickheil/7c89a843bf7c853997a1
![screenshot](https://raw.githubusercontent.com/zigford/USC-SCCM/linux/screenshots/RunningonLinux.png)