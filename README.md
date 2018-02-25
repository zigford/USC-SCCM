# USC-SCCM
Originally written for exclusive use at USC, I've generecized this module and removed references to USC infrastructure.
Now upon initial launch it will query from your local Configuration Manager site server and attempt to discover your site code.
On subsequent launches, this data is read from an XML settings file stored in your %AppData% path.

On linux, requires wmic: https://gist.github.com/rickheil/7c89a843bf7c853997a1
![screenshot](https://raw.githubusercontent.com/zigford/USC-SCCM/linux/screenshots/RunningonLinux.png)
