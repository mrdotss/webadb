Web ADB
=======
A simple webapp and API for managing and manipulating connected Android devices via the Android Device Bridge (ABD).

## Base Code
thanks for [mfinkle/web-adb](https://github.com/mfinkle/web-adb) for simple WebADB, I just refactor the code from python2 to python3, still have some bug, but I'll fix it ASAP.

## Requirements
The following are required on the host machine running Web ADB:
* Python 3.x
* Android SDK (adb file "platform-tools")

## Quick Start
* Clone this project to the host machine
* Run `python <path-to-web-adb>/server.py --port=8888 --adb-path=<path-to-android-sdk>/platform-tools/adb`
* Open `http://localhost:8888` in a browser

## Basic Usage
* Connected devices are listed in the table
* Selecting a device will display a panel below the table with more capabilities.
* The action buttons/images have hover text to help you guess what they do.
* Clicking on a screenshot will send a `tap` to the device and refresh the screeshot.

### Commandline Arguments
* `--port` the local port to bind the server (defaults to `8080`)
* `--adb-path` the path to the `ADB` binary
* `--cert-file` the path to a `PEM` file you want to use to enable `HTTPS` support