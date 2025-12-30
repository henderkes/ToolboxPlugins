# GWToolbox++ Plugins

## $${\color{red}For \space an \space official \space GWToolbox \space plugin, \space check \space the \space gwdevhub/gwtoolboxpp \space repository.}$$
## $${\color{red}This \space repository \space is \space merely \space allow \space people \space to \space set \space up \space their \space own \space plugins \space in \space a \space convenient \space fashion.}$$
## $${\color{red}Do \space not \space file \space any \space complaints \space or \space refer \space to \space this, \space use \space it \space at \space your \space own \space discretion.}$$

## A set of plugins for the popular Guild Wars 1 tool "GWToolbox"

If you don't know what GWToolbox is, see [https://gwtoolbox.com](https://gwtoolbox.com)

## How to download, build, and run
### Requirements
* Visual Studio 2022 version 17.7+. You can download [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/) for free. You will also need the "Desktop development with C++" package.
* C++23 compatible v143 MSVC Platform Toolset
* Windows 11 SDK
* CMake 3.16 or higher. This is integrated in the [Visual Studio Developer PowerShell](https://learn.microsoft.com/en-us/visualstudio/ide/reference/command-prompt-powershell?view=vs-2022). Alternatively download the latest version from [https://cmake.org/download/](https://cmake.org/download/).
* [Git](https://git-scm.com/)

1. Open **Git Bash**. Use all the following commands in **Git Bash**. 

2. Clone the repository: 
`git clone https://github.com/henderkes/ToolboxPlugins.git`

3. Navigate to the ToolboxPlugins folder: 
`cd ToolboxPlugins`

4. Build: `cmake --preset=vcpkg`

5. Open: `cmake --open build`

6. Build the solution.

7. Copy the resulting dlls in `bin/Debug` or `bin/Release` to your GWToolbox plugin folder. Default is `%USERPROFILE%/GWToolboxpp/<ComputerName>/plugins`
