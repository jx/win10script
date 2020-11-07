# win10script
This is an edit of https://github.com/ChrisTitusTech/win10script to remove bloat in the script, remove unnecessary application installations, and remove securty flaws introduced by the script. The only thing this script "installs" is the Microsoft PDF printer, which is useful.

## Main changes

- Does not lower UAC level (VERY bad idea).
- Remove automatic enabling of Dark Mode.
- Remove automatic installation of Chocolatey.
- Does not install any applications.
- Removes all inadvised security tweaks aside from disabling SMB1. None of the security twaks should be done blindly.
- Removes all Server tweaks. Do not run this on servers. Period.
- Does not remove Smart Screen in IE.
- Does not remove GPS location feature.
- Does not disable Maps or Maps updates.
- Does not remove Calculator, Picture Viewer, Alarms, Camera, Sound Recorder.
- Does not remove Windows Store.
- Does not disable PDF and internal Flash in IE and Edge (safer than using plugins).
- Does not make any desktop or taskbar modifications.
- Enables show file extensions, show Control Panel icons. No other Explorer modifications.
- Reduce over 2700 lines to 200.

## Warning

Never run scripts from the internet before reading them and understanding what they do.
